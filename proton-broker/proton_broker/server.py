import asyncio
import concurrent.futures
import json
import logging
import os
import socketserver
import threading
import time
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from .adapter import ProtonCoreAdapter
from .keys import ExitKeyStore
from .provisioner import CatalogProvisioner

logger = logging.getLogger("proton_broker")

MAX_BODY_BYTES = 16 * 1024
PROTON_CALL_TIMEOUT_SECONDS = float(os.environ.get("PROTON_CALL_TIMEOUT_SECONDS", "30"))
PROFILE_SYNC_INTERVAL_SECONDS = float(os.environ.get("PROFILE_SYNC_INTERVAL_SECONDS", "300"))


class ProtonCallTimeout(Exception):
    pass


class EventLoopRunner:
    """Runs every Proton coroutine on one long-lived loop.

    Proton core keeps loop-bound resources (sessions, refreshers), so a fresh
    asyncio.run() per request is unsafe. Calls are bounded by a timeout so a hung
    Proton request cannot stall the broker indefinitely.
    """

    def __init__(self, timeout: float = PROTON_CALL_TIMEOUT_SECONDS) -> None:
        self.timeout = timeout
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(
            target=self.loop.run_forever, name="proton-event-loop", daemon=True
        )
        self.thread.start()

    def run(self, awaitable: Any) -> Any:
        future = asyncio.run_coroutine_threadsafe(_await(awaitable), self.loop)
        try:
            return future.result(timeout=self.timeout)
        except concurrent.futures.TimeoutError as error:
            future.cancel()
            raise ProtonCallTimeout from error


async def _await(awaitable: Any) -> Any:
    return await awaitable


class BrokerApplication:
    def __init__(
        self,
        adapter: Any,
        provisioner: Any = None,
        runner: EventLoopRunner | None = None,
        keys: ExitKeyStore | None = None,
    ) -> None:
        self.adapter = adapter
        self.provisioner = provisioner
        self.keys = keys
        self.pending_two_factor = False
        self.runner = runner or EventLoopRunner()
        # Requests are served on separate threads so /healthz never waits on
        # Proton; account operations themselves are serialized.
        self.lock = threading.Lock()

    def dispatch(
        self, method: str, path: str, body: dict[str, Any]
    ) -> tuple[int, dict[str, Any]]:
        if method == "GET" and path == "/healthz":
            return 200, {"status": "ok"}
        with self.lock:
            return self._dispatch_locked(method, path, body)

    def _dispatch_locked(
        self, method: str, path: str, body: dict[str, Any]
    ) -> tuple[int, dict[str, Any]]:
        try:
            if method == "GET" and path == "/v1/proton/account":
                if self.pending_two_factor:
                    return 200, {"state": "twoFactorRequired"}
                # Also retries starting the refresher if it failed earlier, for
                # example because Proton's API was unreachable at startup.
                self.ensure_background_refresh()
                return 200, self._with_exit_certificates(self._run(self.adapter.account()))
            if method == "GET" and path == "/v1/proton/servers":
                return 200, {"servers": self._run(self.adapter.servers())}
            if method == "POST" and path.startswith("/v1/proton/servers/") and path.endswith("/add"):
                if self.provisioner is None or self.keys is None:
                    return 503, {"error": "server provisioning is not configured"}
                server_id = unquote(path[len("/v1/proton/servers/"):-len("/add")])
                if not server_id or "/" in server_id:
                    raise ValueError("invalid server ID")
                self._provision(server_id, self._exit_identity(server_id))
                return 200, {"serverId": server_id, "state": "added"}
            if method == "POST" and path == "/v1/proton/login":
                username = required_text(body, "username", 320)
                password = required_text(body, "password", 1024)
                result = self._run(self.adapter.login(username, password))
                if result.get("state") == "failed":
                    return 401, {"error": "Proton authentication failed"}
                self.pending_two_factor = result.get("state") == "twoFactorRequired"
                return 200, self._after_authentication(result)
            if method == "POST" and path == "/v1/proton/totp":
                code = required_text(body, "code", 16)
                if not code.isdigit() or len(code) not in (6, 8):
                    raise ValueError("invalid two-factor code")
                result = self._run(self.adapter.submit_totp(code))
                if result.get("state") == "failed":
                    return 401, {"error": "Proton two-factor authentication failed"}
                self.pending_two_factor = result.get("state") == "twoFactorRequired"
                return 200, self._after_authentication(result)
            if method == "POST" and path == "/v1/proton/logout":
                self._run(self.adapter.logout())
                self.pending_two_factor = False
                return 200, {"state": "signedOut"}
            return 404, {"error": "not found"}
        except ProtonCallTimeout:
            return 504, {"error": "Proton service timed out"}
        except PermissionError as error:
            return 401, {"error": str(error)}
        except ValueError as error:
            return 400, {"error": str(error)}
        except Exception:
            return 502, {"error": "Proton service unavailable"}

    def _run(self, awaitable: Any) -> Any:
        return self.runner.run(awaitable)

    def ensure_background_refresh(self) -> bool:
        """Best effort: a failure here must not break the calling request."""
        try:
            return bool(self._run(self.adapter.enable_refresh()))
        except Exception:  # pylint: disable=broad-except
            logger.warning("could not start Proton background refresh", exc_info=True)
            return False

    def _after_authentication(self, result: dict[str, Any]) -> dict[str, Any]:
        """A new sign-in can issue a new WireGuard key, which makes every
        previously imported configuration useless. Start the certificate
        refresher and regenerate the imported configurations."""
        if result.get("state") != "authenticated":
            return result
        self.ensure_background_refresh()
        if self.provisioner is None or self.keys is None:
            return result
        refreshed, failed = 0, []
        for server_id in self.provisioner.server_ids():
            try:
                # Certificates issued under the previous session may be revoked.
                self._provision(server_id, self._exit_identity(server_id, renew=True))
                refreshed += 1
            except Exception:  # pylint: disable=broad-except
                failed.append(server_id)
                logger.warning("could not regenerate configuration for %s", server_id, exc_info=True)
        return {**result, "configurationsRefreshed": refreshed, "configurationsFailed": failed}

    def _exit_identity(self, server_id: str, renew: bool = False) -> dict[str, Any]:
        """The exit's own key, with a certificate that is not due for renewal."""
        record = self.keys.get(server_id)
        if renew or ExitKeyStore.needs_certificate(record):
            record = self._run(
                self.adapter.issue_certificate(record["ed25519"] if record else None)
            )
            self.keys.put(server_id, record)
        return record

    def _provision(self, server_id: str, identity: dict[str, Any]) -> None:
        self.provisioner.add(self._run(self.adapter.provision(server_id, identity["wireguard"])))

    def _with_exit_certificates(self, account: dict[str, Any]) -> dict[str, Any]:
        """Report the exit certificate closest to expiry: that is what fails first."""
        if self.keys is None or self.provisioner is None or account.get("state") != "authenticated":
            return account
        records = [self.keys.get(server_id) for server_id in self.provisioner.server_ids()]
        expiries = [record["expires"] for record in records if record]
        if expiries:
            account = {**account, "certificateValidSeconds": int(min(expiries) - time.time())}
        return account

    def sync_profiles(self) -> tuple[int, list[str]]:
        """Keep every imported exit on its own key with a current certificate.

        Renews certificates when Proton's refresh time passes (the profile does
        not change), and rewrites profiles that do not carry the exit's key:
        profiles from before per-exit keys, restored from a backup, or written
        by an earlier session. Such tunnels complete handshakes but pass nothing.
        Best effort; returns (profiles rewritten, server IDs that failed).
        """
        if self.provisioner is None or self.keys is None:
            return 0, []
        rewritten, failed = 0, []
        with self.lock:
            try:
                if self._run(self.adapter.account()).get("state") != "authenticated":
                    return 0, []
            except Exception:  # pylint: disable=broad-except
                logger.warning("could not read the Proton session state", exc_info=True)
                return 0, []
            for server_id in self.provisioner.server_ids():
                try:
                    identity = self._exit_identity(server_id)
                    if self.provisioner.profile_key(server_id) != identity["wireguard"]:
                        logger.info("rewriting the profile of %s with its own key", server_id)
                        self._provision(server_id, identity)
                        rewritten += 1
                except Exception:  # pylint: disable=broad-except
                    failed.append(server_id)
                    logger.warning("could not update the key or certificate of %s", server_id, exc_info=True)
        return rewritten, failed

    def sync_profiles_forever(self, interval: float = PROFILE_SYNC_INTERVAL_SECONDS) -> None:
        while True:
            self.sync_profiles()
            time.sleep(interval)


def required_text(body: dict[str, Any], field: str, maximum: int) -> str:
    value = body.get(field)
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ValueError(f"invalid {field}")
    return value


class BrokerHandler(BaseHTTPRequestHandler):
    server_version = "ProtonAccountBroker/0.1"

    def do_GET(self) -> None:
        self._dispatch({})

    def do_POST(self) -> None:
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            content_length = -1
        if content_length < 0:
            self._respond(400, {"error": "invalid Content-Length"})
            return
        if content_length > MAX_BODY_BYTES:
            self._respond(413, {"error": "request body too large"})
            return
        try:
            raw = self.rfile.read(content_length)
            body = json.loads(raw) if raw else {}
            if not isinstance(body, dict):
                raise ValueError
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            self._respond(400, {"error": "invalid JSON body"})
            return
        self._dispatch(body)

    def log_message(self, _format: str, *_args: Any) -> None:
        return

    def _dispatch(self, body: dict[str, Any]) -> None:
        status, payload = self.server.application.dispatch(
            self.command, self.path.split("?", 1)[0], body
        )
        self._respond(status, payload)

    def _respond(self, status: int, payload: dict[str, Any]) -> None:
        encoded = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(encoded)


class BrokerServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True

    def __init__(self, socket_path: str, application: BrokerApplication) -> None:
        self.application = application
        super().__init__(socket_path, BrokerHandler)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    os.umask(0o077)
    socket_path = Path(
        os.environ.get(
            "PROTON_BROKER_SOCKET", "/run/tailscale-exit-policy-router/proton.sock"
        )
    )
    socket_path.parent.mkdir(mode=0o770, parents=True, exist_ok=True)
    runtime_directory = os.environ.get("XDG_RUNTIME_DIR")
    if runtime_directory:
        # The shared runtime volume is a fresh tmpfs, so create the broker's private
        # runtime directory on every start.
        Path(runtime_directory).mkdir(mode=0o700, parents=True, exist_ok=True)
    socket_path.unlink(missing_ok=True)
    provisioner = CatalogProvisioner(
        os.environ.get("PROTON_CATALOG_PATH", "/etc/tailscale-exit-policy-router/catalog.json"),
        os.environ.get("PROTON_CONFIGS_PATH", "/run/secrets/proton"),
    )
    keys = ExitKeyStore(
        os.environ.get("EXIT_KEYS_PATH", "/var/lib/proton-broker/exit-keys.json")
    )
    application = BrokerApplication(ProtonCoreAdapter(), provisioner, keys=keys)
    if application.ensure_background_refresh():
        logger.info("Proton background refresh started for the saved session")
    threading.Thread(
        target=application.sync_profiles_forever, name="profile-sync", daemon=True
    ).start()
    with BrokerServer(str(socket_path), application) as server:
        socket_path.chmod(0o660)
        server.serve_forever()


if __name__ == "__main__":
    main()

import asyncio
import json
import os
import socketserver
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from .adapter import ProtonCoreAdapter
from .provisioner import CatalogProvisioner

MAX_BODY_BYTES = 16 * 1024


class BrokerApplication:
    def __init__(self, adapter: Any, provisioner: Any = None) -> None:
        self.adapter = adapter
        self.provisioner = provisioner
        self.pending_two_factor = False

    def dispatch(
        self, method: str, path: str, body: dict[str, Any]
    ) -> tuple[int, dict[str, Any]]:
        try:
            if method == "GET" and path == "/healthz":
                return 200, {"status": "ok"}
            if method == "GET" and path == "/v1/proton/account":
                if self.pending_two_factor:
                    return 200, {"state": "twoFactorRequired"}
                return 200, self._run(self.adapter.account())
            if method == "GET" and path == "/v1/proton/servers":
                return 200, {"servers": self._run(self.adapter.servers())}
            if method == "POST" and path.startswith("/v1/proton/servers/") and path.endswith("/add"):
                if self.provisioner is None:
                    return 503, {"error": "server provisioning is not configured"}
                server_id = unquote(path[len("/v1/proton/servers/"):-len("/add")])
                if not server_id or "/" in server_id:
                    raise ValueError("invalid server ID")
                server = self._run(self.adapter.provision(server_id))
                self.provisioner.add(server)
                return 200, {"serverId": server_id, "state": "added"}
            if method == "POST" and path == "/v1/proton/login":
                username = required_text(body, "username", 320)
                password = required_text(body, "password", 1024)
                result = self._run(self.adapter.login(username, password))
                if result.get("state") == "failed":
                    return 401, {"error": "Proton authentication failed"}
                self.pending_two_factor = result.get("state") == "twoFactorRequired"
                return 200, result
            if method == "POST" and path == "/v1/proton/totp":
                code = required_text(body, "code", 16)
                if not code.isdigit() or len(code) not in (6, 8):
                    raise ValueError("invalid two-factor code")
                result = self._run(self.adapter.submit_totp(code))
                if result.get("state") == "failed":
                    return 401, {"error": "Proton two-factor authentication failed"}
                self.pending_two_factor = result.get("state") == "twoFactorRequired"
                return 200, result
            if method == "POST" and path == "/v1/proton/logout":
                self._run(self.adapter.logout())
                self.pending_two_factor = False
                return 200, {"state": "signedOut"}
            return 404, {"error": "not found"}
        except PermissionError as error:
            return 401, {"error": str(error)}
        except ValueError as error:
            return 400, {"error": str(error)}
        except Exception:
            return 502, {"error": "Proton service unavailable"}

    @staticmethod
    def _run(awaitable: Any) -> Any:
        return asyncio.run(awaitable)


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
        content_length = int(self.headers.get("Content-Length", "0"))
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


class BrokerServer(socketserver.UnixStreamServer):
    def __init__(self, socket_path: str, application: BrokerApplication) -> None:
        self.application = application
        super().__init__(socket_path, BrokerHandler)


def main() -> None:
    os.umask(0o077)
    socket_path = Path(
        os.environ.get(
            "PROTON_BROKER_SOCKET", "/run/proton-policy-router/proton.sock"
        )
    )
    socket_path.parent.mkdir(mode=0o770, parents=True, exist_ok=True)
    socket_path.unlink(missing_ok=True)
    provisioner = CatalogProvisioner(
        os.environ.get("PROTON_CATALOG_PATH", "/etc/proton-policy-router/catalog.json"),
        os.environ.get("PROTON_CONFIGS_PATH", "/run/secrets/proton"),
    )
    with BrokerServer(
        str(socket_path), BrokerApplication(ProtonCoreAdapter(), provisioner)
    ) as server:
        socket_path.chmod(0o660)
        server.serve_forever()


if __name__ == "__main__":
    main()

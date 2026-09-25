import importlib.metadata
import secrets
from typing import Any, Optional


FEATURE_NAMES = {
    1: "secure-core",
    2: "tor",
    4: "p2p",
    8: "streaming",
    16: "ipv6",
}


def sanitize_server(raw: dict[str, Any], user_tier: int) -> dict[str, Any]:
    required_tier = int(raw.get("Tier", 0))
    feature_mask = int(raw.get("Features", 0))
    return {
        "id": str(raw.get("ID", "")),
        "name": str(raw.get("Name", "")),
        "country": str(raw.get("ExitCountry", "")),
        "city": str(raw.get("City") or raw.get("State") or ""),
        "load": int(raw.get("Load", 0)),
        "online": int(raw.get("Status", 0)) == 1,
        "accessible": required_tier <= user_tier,
        "tier": required_tier,
        "features": [
            name for bit, name in FEATURE_NAMES.items() if feature_mask & bit
        ],
    }


class ProtonCoreAdapter:
    def __init__(self) -> None:
        from proton.vpn.core.api import ProtonVPNAPI
        from proton.vpn.core.registry import Registry
        from proton.vpn.core.session_holder import ClientTypeMetadata

        self._api = ProtonVPNAPI(
            ClientTypeMetadata(type="cli"), registry=Registry()
        )
        self._refresh_enabled = False

    @property
    def core_version(self) -> str:
        return importlib.metadata.version("proton-vpn-api-core")

    async def login(self, username: str, password: str) -> dict[str, Any]:
        result = await self._api.login(username, password)
        return self._login_result(result)

    async def submit_totp(self, code: str) -> dict[str, Any]:
        result = await self._api.submit_2fa_code(code)
        return self._login_result(result)

    async def logout(self) -> None:
        await self._api.logout()
        self._refresh_enabled = False

    async def enable_refresh(self) -> bool:
        """Starts Proton's own background refresher, as the official client does.

        Session certificates are valid for about seven days. Proton servers keep
        completing WireGuard handshakes with an expired certificate but stop
        forwarding data, so the certificate must be renewed continuously. The
        refresher also keeps the server list and client configuration current.
        """
        if not self._api.is_user_logged_in():
            return False
        if not self._refresh_enabled:
            await self._api.refresher.enable()
            self._refresh_enabled = True
        return True

    async def current_private_key(self) -> Optional[str]:
        """The session's WireGuard private key, which every profile must use."""
        if not self._api.is_user_logged_in():
            return None
        return self._api.account_data.vpn_credentials.pubkey_credentials.wg_private_key

    def _certificate_remaining_seconds(self) -> Optional[int]:
        try:
            credentials = self._api.account_data.vpn_credentials.pubkey_credentials
            remaining = credentials.certificate_validity_remaining
        except Exception:  # pylint: disable=broad-except
            return None
        return None if remaining is None else int(remaining)

    async def account(self) -> dict[str, Any]:
        if not self._api.is_user_logged_in():
            return {
                "state": "signedOut",
                "coreVersion": self.core_version,
            }
        account = self._api.account_data
        return {
            "state": "authenticated",
            "username": self._api.account_name,
            "plan": account.plan_title,
            "tier": self._api.user_tier,
            "maxConnections": account.max_connections,
            "coreVersion": self.core_version,
            "certificateValidSeconds": self._certificate_remaining_seconds(),
            "backgroundRefresh": self._refresh_enabled,
        }

    async def servers(self) -> list[dict[str, Any]]:
        if not self._api.is_user_logged_in():
            raise PermissionError("Proton account login required")
        server_list = self._api.server_list
        if server_list is None or server_list.expired:
            server_list = await self._api.refresher.get_up_to_date_server_list()
        servers = [
            sanitize_server(server.to_dict(), self._api.user_tier)
            for server in server_list.logicals
        ]
        return sorted(servers, key=lambda server: (server["country"], server["city"], server["name"]))

    async def provision(self, server_id: str) -> dict[str, Any]:
        if not self._api.is_user_logged_in():
            raise PermissionError("Proton account login required")
        server_list = self._api.server_list
        if server_list is None or server_list.expired:
            server_list = await self._api.refresher.get_up_to_date_server_list()
        logical = next(
            (server for server in server_list.logicals if server.id == server_id),
            None,
        )
        if logical is None:
            raise ValueError("unknown Proton server")
        if logical.tier > self._api.user_tier:
            raise ValueError("server is not available on this Proton plan")
        physical_servers = [server for server in logical.physical_servers if server.enabled]
        if not physical_servers:
            raise ValueError("server has no online WireGuard endpoint")
        physical = secrets.choice(physical_servers)
        credentials = self._api.account_data.vpn_credentials.pubkey_credentials
        config = (
            "[Interface]\n"
            f"PrivateKey = {credentials.wg_private_key}\n"
            "Address = 10.2.0.2/32\n"
            "DNS = 10.2.0.1\n\n"
            "[Peer]\n"
            f"PublicKey = {physical.x25519_pk}\n"
            "AllowedIPs = 0.0.0.0/0\n"
            f"Endpoint = {physical.entry_ip}:51820\n"
            "PersistentKeepalive = 25\n"
        )
        metadata = sanitize_server(logical.to_dict(), self._api.user_tier)
        metadata["config"] = config
        return metadata

    def _login_result(self, result: Any) -> dict[str, Any]:
        if not result.authenticated:
            return {"state": "failed"}
        if result.twofa_required:
            return {"state": "twoFactorRequired"}
        return {"state": "authenticated"}

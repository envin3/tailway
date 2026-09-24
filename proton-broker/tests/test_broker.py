import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1]))

from proton_broker.adapter import sanitize_server
from proton_broker.server import BrokerApplication
from proton_broker.provisioner import CatalogProvisioner


class FakeProvisioner:
    def __init__(self):
        self.server = None

    def add(self, server):
        self.server = server


class FakeAdapter:
    def __init__(self) -> None:
        self.logged_in = False
        self.two_factor_required = False
        self.login_call = None

    async def login(self, username, password):
        self.login_call = (username, password)
        if password == "wrong":
            return {"state": "failed"}
        self.two_factor_required = True
        return {"state": "twoFactorRequired"}

    async def submit_totp(self, code):
        self.two_factor_required = False
        self.logged_in = True
        return {"state": "authenticated"}

    async def logout(self):
        self.logged_in = False

    async def account(self):
        return {"state": "authenticated" if self.logged_in else "signedOut"}

    async def servers(self):
        if not self.logged_in:
            raise PermissionError("Proton account login required")
        return [{"id": "logical-1", "name": "CH#1"}]

    async def provision(self, server_id):
        return {
            "id": server_id,
            "name": "CH#1",
            "country": "CH",
            "city": "Zurich",
            "features": ["p2p"],
            "config": "private transport material",
        }


class BrokerApplicationTests(unittest.TestCase):
    def setUp(self):
        self.adapter = FakeAdapter()
        self.application = BrokerApplication(self.adapter)

    def test_health(self):
        status, payload = self.application.dispatch("GET", "/healthz", {})
        self.assertEqual(status, 200)
        self.assertEqual(payload, {"status": "ok"})

    def test_login_and_totp_flow(self):
        status, payload = self.application.dispatch(
            "POST", "/v1/proton/login", {"username": "user", "password": "secret"}
        )
        self.assertEqual((status, payload), (200, {"state": "twoFactorRequired"}))
        self.assertEqual(self.adapter.login_call, ("user", "secret"))
        self.assertNotIn("secret", repr(payload))
        self.assertEqual(
            self.application.dispatch("GET", "/v1/proton/account", {}),
            (200, {"state": "twoFactorRequired"}),
        )

        status, payload = self.application.dispatch(
            "POST", "/v1/proton/totp", {"code": "123456"}
        )
        self.assertEqual((status, payload), (200, {"state": "authenticated"}))

    def test_rejects_invalid_totp(self):
        status, payload = self.application.dispatch(
            "POST", "/v1/proton/totp", {"code": "abc"}
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"], "invalid two-factor code")

    def test_rejects_invalid_credentials(self):
        status, payload = self.application.dispatch(
            "POST", "/v1/proton/login", {"username": "user", "password": "wrong"}
        )
        self.assertEqual(status, 401)
        self.assertEqual(payload["error"], "Proton authentication failed")

    def test_servers_require_login(self):
        status, payload = self.application.dispatch("GET", "/v1/proton/servers", {})
        self.assertEqual(status, 401)
        self.assertEqual(payload["error"], "Proton account login required")

    def test_logout_clears_state(self):
        self.adapter.logged_in = True
        status, payload = self.application.dispatch("POST", "/v1/proton/logout", {})
        self.assertEqual((status, payload), (200, {"state": "signedOut"}))
        self.assertFalse(self.adapter.logged_in)

    def test_adds_discovered_server(self):
        provisioner = FakeProvisioner()
        application = BrokerApplication(self.adapter, provisioner)
        status, payload = application.dispatch(
            "POST", "/v1/proton/servers/logical%2D1/add", {}
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload, {"serverId": "logical-1", "state": "added"})
        self.assertEqual(provisioner.server["id"], "logical-1")


class CatalogProvisionerTests(unittest.TestCase):
    def test_writes_agent_catalog_and_private_config(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            catalog = root / "catalog.json"
            configs = root / "configs"
            configs.mkdir()
            catalog.write_text('{"schemaVersion":1,"servers":[]}')
            CatalogProvisioner(str(catalog), str(configs)).add({
                "id": "logical-1",
                "name": "CH#1",
                "country": "CH",
                "city": "Zurich",
                "features": ["p2p"],
                "config": "[Interface]\nPrivateKey = secret\n",
            })

            data = __import__("json").loads(catalog.read_text())
            self.assertEqual(data["servers"][0]["id"], "logical-1")
            config = configs / data["servers"][0]["configFile"]
            self.assertEqual(config.read_text(), "[Interface]\nPrivateKey = secret\n")
            self.assertEqual(config.stat().st_mode & 0o777, 0o640)


class ServerSanitizationTests(unittest.TestCase):
    def test_exposes_only_safe_metadata(self):
        raw = {
            "ID": "logical-1",
            "Name": "CH#1",
            "ExitCountry": "CH",
            "City": "Zurich",
            "Load": 42,
            "Status": 1,
            "Tier": 2,
            "Features": 5,
            "Servers": [{"EntryIP": "192.0.2.1", "X25519PublicKey": "private"}],
        }
        server = sanitize_server(raw, user_tier=1)
        self.assertEqual(server["features"], ["secure-core", "p2p"])
        self.assertFalse(server["accessible"])
        self.assertNotIn("Servers", server)
        self.assertNotIn("EntryIP", repr(server))
        self.assertNotIn("X25519PublicKey", repr(server))


if __name__ == "__main__":
    unittest.main()

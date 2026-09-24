import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1]))

from proton_broker.adapter import sanitize_server
from proton_broker.server import BrokerApplication, EventLoopRunner
from proton_broker.provisioner import CatalogProvisioner


class FakeProvisioner:
    def __init__(self, server_ids=()):
        self.server = None
        self.added = []
        self.ids = list(server_ids)

    def server_ids(self):
        return list(self.ids)

    def add(self, server):
        self.server = server
        self.added.append(server["id"])


class FakeAdapter:
    def __init__(self) -> None:
        self.logged_in = False
        self.two_factor_required = False
        self.login_call = None
        self.refresh_enabled = False
        self.refresh_error = None

    async def enable_refresh(self):
        if self.refresh_error:
            raise self.refresh_error
        if not self.logged_in:
            return False
        self.refresh_enabled = True
        return True

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


class BackgroundRefreshTests(unittest.TestCase):
    def sign_in(self, application, adapter):
        application.dispatch("POST", "/v1/proton/login", {"username": "u", "password": "p"})
        return application.dispatch("POST", "/v1/proton/totp", {"code": "123456"})

    def test_sign_in_starts_refresh_and_regenerates_imported_configs(self):
        adapter = FakeAdapter()
        provisioner = FakeProvisioner(["logical-1", "logical-2"])
        application = BrokerApplication(adapter, provisioner)
        status, payload = self.sign_in(application, adapter)
        self.assertEqual(status, 200)
        self.assertTrue(adapter.refresh_enabled)
        self.assertEqual(provisioner.added, ["logical-1", "logical-2"])
        self.assertEqual(payload["configurationsRefreshed"], 2)
        self.assertEqual(payload["configurationsFailed"], [])

    def test_account_poll_starts_refresh_for_a_saved_session(self):
        adapter = FakeAdapter()
        adapter.logged_in = True
        application = BrokerApplication(adapter)
        status, _ = application.dispatch("GET", "/v1/proton/account", {})
        self.assertEqual(status, 200)
        self.assertTrue(adapter.refresh_enabled)

    def test_refresh_failure_does_not_break_account_status(self):
        adapter = FakeAdapter()
        adapter.logged_in = True
        adapter.refresh_error = RuntimeError("API unreachable")
        application = BrokerApplication(adapter)
        status, payload = application.dispatch("GET", "/v1/proton/account", {})
        self.assertEqual(status, 200)
        self.assertEqual(payload["state"], "authenticated")
        self.assertFalse(adapter.refresh_enabled)


class SlowAdapter(FakeAdapter):
    def __init__(self, delay):
        super().__init__()
        self.delay = delay
        self.loops = []

    async def account(self):
        import asyncio

        self.loops.append(asyncio.get_running_loop())
        await asyncio.sleep(self.delay)
        return {"state": "signedOut"}


class EventLoopRunnerTests(unittest.TestCase):
    def test_hung_proton_call_times_out(self):
        application = BrokerApplication(SlowAdapter(5), runner=EventLoopRunner(timeout=0.2))
        status, payload = application.dispatch("GET", "/v1/proton/account", {})
        self.assertEqual(status, 504)
        self.assertIn("timed out", payload["error"])

    def test_health_does_not_wait_for_proton(self):
        import threading
        import time

        application = BrokerApplication(SlowAdapter(1), runner=EventLoopRunner(timeout=5))
        worker = threading.Thread(
            target=application.dispatch, args=("GET", "/v1/proton/account", {})
        )
        worker.start()
        time.sleep(0.1)
        started = time.monotonic()
        status, _ = application.dispatch("GET", "/healthz", {})
        self.assertEqual(status, 200)
        self.assertLess(time.monotonic() - started, 0.5)
        worker.join()

    def test_calls_share_one_event_loop(self):
        adapter = SlowAdapter(0)
        application = BrokerApplication(adapter)
        application.dispatch("GET", "/v1/proton/account", {})
        application.dispatch("GET", "/v1/proton/account", {})
        self.assertEqual(len(adapter.loops), 2)
        self.assertIs(adapter.loops[0], adapter.loops[1])


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

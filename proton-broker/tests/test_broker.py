import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1]))

from proton_broker.adapter import sanitize_server
from proton_broker.server import BrokerApplication, EventLoopRunner
from proton_broker.keys import ExitKeyStore
from proton_broker.provisioner import CatalogProvisioner


def key_store():
    directory = tempfile.TemporaryDirectory()
    store = ExitKeyStore(str(Path(directory.name) / "exit-keys.json"))
    store.directory = directory  # keep the directory alive with the store
    return store


class FakeProvisioner:
    def __init__(self, server_ids=()):
        self.server = None
        self.added = []
        self.ids = list(server_ids)
        self.keys = {}

    def server_ids(self):
        return list(self.ids)

    def profile_key(self, server_id):
        return self.keys.get(server_id)

    def add(self, server):
        self.server = server
        self.added.append(server["id"])
        self.keys[server["id"]] = server.get("key")


class FakeAdapter:
    def __init__(self) -> None:
        self.logged_in = False
        self.two_factor_required = False
        self.login_call = None
        self.refresh_enabled = False
        self.refresh_error = None
        self.issued = []
        self.provision_error = None

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

    async def issue_certificate(self, ed25519_private_key):
        if not self.logged_in:
            raise PermissionError("Proton account login required")
        ed25519 = ed25519_private_key or f"ed-{len(self.issued)}"
        self.issued.append(ed25519)
        return {"ed25519": ed25519, "wireguard": f"wg-{ed25519}", "expires": 2_000_000_000, "refresh": 1_900_000_000}

    async def provision(self, server_id, private_key):
        if self.provision_error:
            raise self.provision_error
        return {
            "key": private_key,
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

    def test_adds_discovered_server_with_its_own_key(self):
        self.adapter.logged_in = True
        provisioner = FakeProvisioner()
        keys = key_store()
        application = BrokerApplication(self.adapter, provisioner, keys=keys)
        status, payload = application.dispatch(
            "POST", "/v1/proton/servers/logical%2D1/add", {}
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload, {"serverId": "logical-1", "state": "added"})
        self.assertEqual(provisioner.server["id"], "logical-1")
        self.assertEqual(provisioner.server["key"], "wg-ed-0")
        self.assertEqual(keys.get("logical-1")["ed25519"], "ed-0")
        application.dispatch("POST", "/v1/proton/servers/logical-2/add", {})
        self.assertEqual(provisioner.server["key"], "wg-ed-1")


class BackgroundRefreshTests(unittest.TestCase):
    def sign_in(self, application, adapter):
        application.dispatch("POST", "/v1/proton/login", {"username": "u", "password": "p"})
        return application.dispatch("POST", "/v1/proton/totp", {"code": "123456"})

    def test_sign_in_starts_refresh_and_regenerates_imported_configs(self):
        adapter = FakeAdapter()
        provisioner = FakeProvisioner(["logical-1", "logical-2"])
        keys = key_store()
        keys.put("logical-1", {"ed25519": "kept", "wireguard": "wg-kept", "expires": 2_000_000_000, "refresh": 1_900_000_000})
        application = BrokerApplication(adapter, provisioner, keys=keys)
        status, payload = self.sign_in(application, adapter)
        self.assertEqual(status, 200)
        self.assertTrue(adapter.refresh_enabled)
        self.assertEqual(provisioner.added, ["logical-1", "logical-2"])
        self.assertEqual(payload["configurationsRefreshed"], 2)
        self.assertEqual(payload["configurationsFailed"], [])
        # Keys survive a new sign-in; only the certificates are renewed.
        self.assertEqual(adapter.issued, ["kept", "ed-1"])
        self.assertEqual(provisioner.keys["logical-1"], "wg-kept")

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


class ProfileSyncTests(unittest.TestCase):
    def setUp(self):
        self.adapter = FakeAdapter()
        self.adapter.logged_in = True
        self.keys = key_store()

    def test_gives_every_exit_its_own_key_once(self):
        provisioner = FakeProvisioner(["a", "b"])
        provisioner.keys = {"a": "old-shared-session-key", "b": "old-shared-session-key"}
        application = BrokerApplication(self.adapter, provisioner, keys=self.keys)
        self.assertEqual(application.sync_profiles(), (2, []))
        self.assertEqual(provisioner.keys, {"a": "wg-ed-0", "b": "wg-ed-1"})
        self.assertEqual(application.sync_profiles(), (0, []))
        self.assertEqual(self.adapter.issued, ["ed-0", "ed-1"])

    def test_renews_due_certificates_without_rewriting_profiles(self):
        provisioner = FakeProvisioner(["a"])
        provisioner.keys = {"a": "wg-kept"}
        self.keys.put("a", {"ed25519": "kept", "wireguard": "wg-kept", "expires": 10, "refresh": 5})
        application = BrokerApplication(self.adapter, provisioner, keys=self.keys)
        self.assertEqual(application.sync_profiles(), (0, []))
        self.assertEqual(self.adapter.issued, ["kept"])
        self.assertEqual(self.keys.get("a")["refresh"], 1_900_000_000)
        self.assertEqual(provisioner.added, [])

    def test_does_nothing_while_signed_out_or_unconfigured(self):
        self.adapter.logged_in = False
        provisioner = FakeProvisioner(["a"])
        self.assertEqual(BrokerApplication(self.adapter, provisioner, keys=self.keys).sync_profiles(), (0, []))
        self.assertEqual(BrokerApplication(self.adapter, provisioner).sync_profiles(), (0, []))
        self.assertEqual(self.adapter.issued, [])

    def test_reports_exits_that_could_not_be_updated(self):
        self.adapter.provision_error = ValueError("server has no online WireGuard endpoint")
        application = BrokerApplication(self.adapter, FakeProvisioner(["a"]), keys=self.keys)
        self.assertEqual(application.sync_profiles(), (0, ["a"]))

    def test_account_reports_the_exit_certificate_closest_to_expiry(self):
        provisioner = FakeProvisioner(["a", "b"])
        import time
        now = time.time()
        self.keys.put("a", {"ed25519": "a", "wireguard": "wg-a", "expires": now + 7200, "refresh": now + 3600})
        self.keys.put("b", {"ed25519": "b", "wireguard": "wg-b", "expires": now + 90000, "refresh": now + 80000})
        application = BrokerApplication(self.adapter, provisioner, keys=self.keys)
        _, payload = application.dispatch("GET", "/v1/proton/account", {})
        self.assertAlmostEqual(payload["certificateValidSeconds"], 7200, delta=5)


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


class ProfileKeyTests(unittest.TestCase):
    def test_reads_the_single_private_key_of_a_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            configs = root / "configs"
            configs.mkdir()
            (configs / "a.conf").write_text("[Interface]\nPrivateKey = abc=\n[Peer]\n")
            (configs / "b.conf").write_text("[Interface]\nPrivateKey = x\nPrivateKey = y\n")
            catalog = root / "catalog.json"
            catalog.write_text(__import__("json").dumps({"servers": [
                {"id": "a", "configFile": "a.conf"},
                {"id": "b", "configFile": "b.conf"},
                {"id": "c", "configFile": "c.conf"},
            ]}))
            provisioner = CatalogProvisioner(str(catalog), str(configs))
            self.assertEqual(provisioner.profile_key("a"), "abc=")
            self.assertIsNone(provisioner.profile_key("b"))
            self.assertIsNone(provisioner.profile_key("c"))
            self.assertIsNone(provisioner.profile_key("missing"))


class ExitKeyStoreTests(unittest.TestCase):
    def test_persists_records_privately(self):
        store = key_store()
        store.put("a", {"ed25519": "x", "refresh": 5})
        self.assertEqual(ExitKeyStore(str(store.path)).get("a"), {"ed25519": "x", "refresh": 5})
        self.assertEqual(store.path.stat().st_mode & 0o777, 0o600)
        self.assertTrue(ExitKeyStore.needs_certificate(None))
        self.assertTrue(ExitKeyStore.needs_certificate({"refresh": 5}, now=10))
        self.assertFalse(ExitKeyStore.needs_certificate({"refresh": 50}, now=10))


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

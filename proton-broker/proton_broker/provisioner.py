import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Optional


class CatalogProvisioner:
    def __init__(self, catalog_path: str, configs_path: str) -> None:
        self.catalog_path = Path(catalog_path)
        self.configs_path = Path(configs_path)

    def server_ids(self) -> list[str]:
        """IDs of every server already imported into the agent catalog."""
        try:
            catalog = json.loads(self.catalog_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return []
        return [server["id"] for server in catalog.get("servers", []) if server.get("id")]

    def profile_key(self, server_id: str) -> Optional[str]:
        """The WireGuard private key in a server's profile, if it has exactly one."""
        try:
            catalog = json.loads(self.catalog_path.read_text(encoding="utf-8"))
            entry = next(server for server in catalog.get("servers", []) if server.get("id") == server_id)
            config = (self.configs_path / entry["configFile"]).read_text(encoding="utf-8")
        except (FileNotFoundError, StopIteration, KeyError, OSError, ValueError):
            return None
        keys = [
            line.split("=", 1)[1].strip()
            for line in config.splitlines()
            if "=" in line and line.split("=", 1)[0].strip() == "PrivateKey"
        ]
        return keys[0] if len(keys) == 1 else None

    def add(self, server: dict[str, Any]) -> None:
        filename = f"live-{hashlib.sha256(server['id'].encode()).hexdigest()[:24]}.conf"
        self.configs_path.mkdir(mode=0o2770, parents=True, exist_ok=True)
        self._atomic_write(self.configs_path / filename, server["config"], 0o640)

        catalog = json.loads(self.catalog_path.read_text(encoding="utf-8"))
        entry = {
            "id": server["id"],
            "country": server["country"],
            "city": server["city"],
            "name": server["name"],
            "features": server["features"],
            "configFile": filename,
        }
        catalog["servers"] = [
            existing for existing in catalog.get("servers", [])
            if existing.get("id") != server["id"]
        ] + [entry]
        self._atomic_write(
            self.catalog_path,
            json.dumps(catalog, indent=2, sort_keys=True) + "\n",
            0o640,
        )

    @staticmethod
    def _atomic_write(path: Path, content: str, mode: int) -> None:
        descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as file:
                file.write(content)
                file.flush()
                os.fsync(file.fileno())
            os.chmod(temporary, mode)
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
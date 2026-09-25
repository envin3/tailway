import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any, Optional


class ExitKeyStore:
    """Per-exit WireGuard identities.

    Proton tracks one active server per WireGuard key: when several tunnels share
    the session key, the servers keep taking the session from each other and
    each tunnel drops traffic for seconds at a time. Every imported exit
    therefore gets its own key and certificate. A record holds the Ed25519
    private key (base64; the WireGuard key is derived from it) and the
    certificate's expiration and refresh times (Unix seconds).
    """

    def __init__(self, path: str) -> None:
        self.path = Path(path)

    def load(self) -> dict[str, dict[str, Any]]:
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}

    def get(self, server_id: str) -> Optional[dict[str, Any]]:
        return self.load().get(server_id)

    def put(self, server_id: str, record: dict[str, Any]) -> None:
        records = self.load()
        records[server_id] = record
        self._write(records)

    @staticmethod
    def needs_certificate(record: Optional[dict[str, Any]], now: Optional[float] = None) -> bool:
        now = time.time() if now is None else now
        return record is None or now >= record.get("refresh", 0)

    def _write(self, records: dict[str, dict[str, Any]]) -> None:
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(prefix=f".{self.path.name}.", dir=self.path.parent)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as file:
                json.dump(records, file, indent=2, sort_keys=True)
                file.flush()
                os.fsync(file.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, self.path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

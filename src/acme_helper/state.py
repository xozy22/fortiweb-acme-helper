"""Persistenter Zustand: was wurde wohin deployt, welche TXT-Records sind offen."""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _atomic_write(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=path.name, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, sort_keys=True)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _read_json(path: Path, default: Any) -> Any:
    if not path.is_file():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


class DeployState:
    """deployed.json: {cert_name: {fortiweb: {fingerprint, fw_cert_name, deployed_at, ...}}}"""

    def __init__(self, state_dir: Path):
        self.path = state_dir / "deployed.json"
        self._data: dict[str, dict[str, dict]] = _read_json(self.path, {})

    def get(self, cert: str, fortiweb: str) -> dict | None:
        if cert.startswith("_"):
            return None
        return self._data.get(cert, {}).get(fortiweb)

    def set(
        self,
        cert: str,
        fortiweb: str,
        *,
        fingerprint: str,
        fw_cert_name: str,
        extra: dict | None = None,
    ) -> None:
        entry = {
            "fingerprint": fingerprint,
            "fw_cert_name": fw_cert_name,
            "deployed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        if extra:
            entry.update(extra)
        self._data.setdefault(cert, {})[fortiweb] = entry
        _atomic_write(self.path, self._data)

    def all(self) -> dict[str, dict[str, dict]]:
        return self._data

    # Intermediate-Zertifikate: FortiWeb vergibt die Namen selbst, daher Fingerprint -> Name je FortiWeb.
    # Abgelegt unter dem reservierten Schlüssel "_intermediates".
    def intermediate_name(self, fortiweb: str, fingerprint: str) -> str | None:
        return self._data.get("_intermediates", {}).get(fortiweb, {}).get(fingerprint)

    def set_intermediate_name(self, fortiweb: str, fingerprint: str, fw_name: str) -> None:
        self._data.setdefault("_intermediates", {}).setdefault(fortiweb, {})[fingerprint] = fw_name
        _atomic_write(self.path, self._data)


class PendingTxtState:
    """pending_txt.json: TXT-Records, die im laufenden certbot-Lauf gesetzt wurden.

    Der Auth-Hook befüllt die Liste, damit beim letzten Challenge auf alle Records
    gleichzeitig gewartet werden kann. Der Cleanup-Hook leert sie.
    """

    def __init__(self, state_dir: Path):
        self.path = state_dir / "pending_txt.json"

    def add(self, fqdn: str, value: str, provider: str) -> None:
        items = _read_json(self.path, [])
        items.append({"fqdn": fqdn, "value": value, "provider": provider})
        _atomic_write(self.path, items)

    def items(self) -> list[dict]:
        return _read_json(self.path, [])

    def clear(self) -> None:
        if self.path.exists():
            self.path.unlink()

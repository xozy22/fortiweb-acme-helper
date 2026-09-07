"""do.de / Domain-Offensive Let's-Encrypt-API.

GET https://my.do.de/api/letsencrypt?token=T&domain=_acme-challenge.example.de&value=V
GET https://my.do.de/api/letsencrypt?token=T&domain=_acme-challenge.example.de&action=delete
Erfolg: Antwort enthält "success".
"""

from __future__ import annotations

import logging

import requests

from ..config import DodeProvider, env_secret
from ..errors import DnsError

log = logging.getLogger(__name__)


class DodeDns:
    def __init__(self, name: str, cfg: DodeProvider):
        self.name = name
        self.cfg = cfg
        self.token = env_secret(cfg.token_env, what=f"dns_providers.{name}.token_env")
        self.session = requests.Session()

    def _call(self, params: dict) -> str:
        params = {"token": self.token, **params}
        try:
            resp = self.session.get(self.cfg.api_url, params=params, timeout=30)
        except requests.RequestException as exc:
            raise DnsError(f"do.de nicht erreichbar: {exc}") from exc
        text = resp.text.strip()
        ok = resp.status_code < 400 and "success" in text.lower()
        try:
            parsed = resp.json()
            if isinstance(parsed, dict) and "success" in parsed:
                ok = ok and bool(parsed["success"])
        except ValueError:
            pass
        if not ok:
            safe = text.replace(self.token, "***")[:300]
            raise DnsError(f"do.de-API meldete Fehler ({resp.status_code}): {safe}")
        return text

    def add_txt(self, fqdn: str, value: str) -> None:
        self._call({"domain": fqdn, "value": value})
        log.info("do.de: TXT %s gesetzt", fqdn)

    def remove_txt(self, fqdn: str, value: str) -> None:
        # Die API löscht alle TXT-Werte unter dem Namen; der Wert ist nicht adressierbar.
        try:
            self._call({"domain": fqdn, "action": "delete"})
            log.info("do.de: TXT %s entfernt", fqdn)
        except DnsError as exc:
            log.warning("do.de: Löschen von %s nicht bestätigt: %s", fqdn, exc)

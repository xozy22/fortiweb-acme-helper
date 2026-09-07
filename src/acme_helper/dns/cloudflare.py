"""Cloudflare DNS über API-Token (Zone:DNS:Edit, Zone:Zone:Read)."""

from __future__ import annotations

import logging

import requests

from ..config import CloudflareProvider, env_secret
from ..errors import DnsError

log = logging.getLogger(__name__)


class CloudflareDns:
    def __init__(self, name: str, cfg: CloudflareProvider):
        self.name = name
        self.cfg = cfg
        token = env_secret(cfg.api_token_env, what=f"dns_providers.{name}.api_token_env")
        self.session = requests.Session()
        self.session.headers.update({"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
        self._zone_cache: dict[str, str] = {}

    # --- HTTP --------------------------------------------------------------
    def _call(self, method: str, path: str, **kw) -> dict:
        url = f"{self.cfg.api_url.rstrip('/')}{path}"
        try:
            resp = self.session.request(method, url, timeout=30, **kw)
        except requests.RequestException as exc:
            raise DnsError(f"Cloudflare nicht erreichbar: {exc}") from exc
        try:
            body = resp.json()
        except ValueError:
            raise DnsError(f"Cloudflare: keine JSON-Antwort ({resp.status_code})")
        if not body.get("success", False):
            errors = "; ".join(f"{e.get('code')}: {e.get('message')}" for e in body.get("errors", []))
            raise DnsError(f"Cloudflare {method} {path} fehlgeschlagen: {errors or resp.status_code}")
        return body

    # --- Zone --------------------------------------------------------------
    def zone_id(self, fqdn: str) -> str:
        """Sucht die Zone, indem vom FQDN aus Suffixe probiert werden."""
        labels = fqdn.rstrip(".").lower().split(".")
        for i in range(len(labels) - 1):
            candidate = ".".join(labels[i:])
            if candidate in self._zone_cache:
                return self._zone_cache[candidate]
            body = self._call("GET", "/zones", params={"name": candidate, "status": "active"})
            if body.get("result"):
                zid = body["result"][0]["id"]
                self._zone_cache[candidate] = zid
                log.debug("Cloudflare-Zone für %s: %s (%s)", fqdn, candidate, zid)
                return zid
        raise DnsError(f"Cloudflare: keine Zone für {fqdn} gefunden (Token-Berechtigung prüfen)")

    # --- Records -----------------------------------------------------------
    def _find_records(self, zid: str, fqdn: str, value: str) -> list[dict]:
        body = self._call("GET", f"/zones/{zid}/dns_records", params={"type": "TXT", "name": fqdn, "per_page": 100})
        out = []
        for rec in body.get("result", []):
            content = str(rec.get("content", "")).strip('"')
            if content == value:
                out.append(rec)
        return out

    def add_txt(self, fqdn: str, value: str) -> None:
        zid = self.zone_id(fqdn)
        if self._find_records(zid, fqdn, value):
            log.info("Cloudflare: TXT %s existiert bereits", fqdn)
            return
        self._call(
            "POST",
            f"/zones/{zid}/dns_records",
            json={"type": "TXT", "name": fqdn, "content": value, "ttl": self.cfg.ttl},
        )
        log.info("Cloudflare: TXT %s gesetzt", fqdn)

    def remove_txt(self, fqdn: str, value: str) -> None:
        zid = self.zone_id(fqdn)
        for rec in self._find_records(zid, fqdn, value):
            self._call("DELETE", f"/zones/{zid}/dns_records/{rec['id']}")
            log.info("Cloudflare: TXT %s entfernt", fqdn)

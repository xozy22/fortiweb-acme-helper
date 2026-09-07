"""Strato: kein API, daher Automatisierung des Kundenlogins (Web-Oberfläche).

Mechanik nach dem MIT-lizenzierten Projekt Buxdehuda/strato-certbot:
  1. POST Login (identifier, passwd), optional TOTP-Formular
  2. sessionID aus der Redirect-URL
  3. Paket (cID) über die Paketliste finden, in dem die Domain liegt
  4. TXT-Records der Domain lesen (node=ManageDomains, action_show_txt_records)
  5. Komplette Liste inkl. neuem Record zurückschreiben (action_change_txt_records)

Bricht bei Änderungen an der Strato-Oberfläche. Bei Fehlern wird das HTML unter
<data>/debug abgelegt, um die Selektoren anpassen zu können.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import pyotp
import requests
from bs4 import BeautifulSoup

from ..config import StratoProvider, env_secret
from ..errors import DnsError

log = logging.getLogger(__name__)


@dataclass
class TxtRecord:
    prefix: str
    type: str
    value: str


class StratoClient:
    def __init__(
        self,
        *,
        api_url: str,
        username: str,
        password: str,
        totp_secret: str | None = None,
        totp_devicename: str | None = None,
        debug_dir: Path | None = None,
        session: requests.Session | None = None,
    ):
        self.api_url = api_url
        self.username = username
        self.password = password
        self.totp_secret = totp_secret
        self.totp_devicename = totp_devicename
        self.debug_dir = debug_dir
        self.http = session or requests.Session()
        self.http.headers.setdefault(
            "User-Agent", "Mozilla/5.0 (X11; Linux x86_64) acme-helper/1.0"
        )
        self.session_id: str | None = None

    # --- Hilfsfunktionen ---------------------------------------------------
    def _dump(self, stage: str, html: str) -> None:
        if not self.debug_dir:
            return
        try:
            self.debug_dir.mkdir(parents=True, exist_ok=True)
            stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            path = self.debug_dir / f"strato-{stage}-{stamp}.html"
            path.write_text(html, encoding="utf-8")
            log.warning("Strato-HTML für Analyse gespeichert: %s", path)
        except OSError as exc:
            log.debug("Debug-Dump fehlgeschlagen: %s", exc)

    def _get(self, params: dict) -> requests.Response:
        try:
            return self.http.get(self.api_url, params=params, timeout=60)
        except requests.RequestException as exc:
            raise DnsError(f"Strato nicht erreichbar: {exc}") from exc

    def _post(self, data: dict) -> requests.Response:
        try:
            return self.http.post(self.api_url, data=data, timeout=60)
        except requests.RequestException as exc:
            raise DnsError(f"Strato nicht erreichbar: {exc}") from exc

    # --- Login -------------------------------------------------------------
    def _login_2fa(self, response: requests.Response) -> requests.Response:
        soup = BeautifulSoup(response.text, "html.parser")
        if soup.find("h1", string=re.compile("Zwei-Faktor-Authentifizierung")) is None:
            return response
        if not self.totp_secret:
            self._dump("2fa-required", response.text)
            raise DnsError("Strato verlangt 2FA, aber es ist kein totp_secret konfiguriert")
        token_input = soup.find("input", {"name": "totp_token"})
        if token_input is None or not token_input.get("value"):
            self._dump("2fa-token", response.text)
            raise DnsError("Strato-2FA-Seite: totp_token nicht gefunden")
        pw_id = None
        options = soup.find_all("option")
        if self.totp_devicename:
            for opt in options:
                if self.totp_devicename in opt.get_text():
                    pw_id = opt.get("value")
                    break
        if pw_id is None and options:
            pw_id = options[0].get("value")
        if pw_id is None:
            self._dump("2fa-device", response.text)
            raise DnsError("Strato-2FA-Seite: kein Gerät (pw_id) gefunden")
        code = pyotp.TOTP(self.totp_secret).now()
        return self._post(
            {
                "identifier": self.username,
                "action_customer_login.x": 1,
                "totp_token": token_input["value"],
                "pw_id": pw_id,
                "totp": code,
            }
        )

    def login(self) -> None:
        self._get({})  # Cookies holen
        response = self._post(
            {"identifier": self.username, "passwd": self.password, "action_customer_login.x": "Login"}
        )
        response = self._login_2fa(response)
        match = re.search(r"sessionID=([^&]+)", response.url)
        if not match:
            self._dump("login", response.text)
            raise DnsError("Strato-Login fehlgeschlagen (keine sessionID in der Antwort-URL)")
        self.session_id = match.group(1)
        log.info("Strato: Login erfolgreich")

    # --- Pakete / Domains --------------------------------------------------
    def list_packages(self) -> list[tuple[str, str]]:
        """Liefert [(cID, Beschreibungstext)] aller Pakete."""
        response = self._get({"sessionID": self.session_id, "cID": 0, "node": "kds_CustomerEntryPage"})
        soup = BeautifulSoup(response.text, "html.parser")
        table = soup.select_one("#package_list")
        if table is None:
            self._dump("packages", response.text)
            raise DnsError("Strato: Paketliste (#package_list) nicht gefunden")
        packages: list[tuple[str, str]] = []
        for row in table.select("tbody > tr"):
            info = row.select_one(".package-information")
            link = row.select_one(".jss_with_own_packagename a")
            if info is None or link is None:
                continue
            m = re.search(r"cID=(\d+)", link.get("href", ""))
            if not m:
                continue
            packages.append((m.group(1), " ".join(info.get_text(" ").split())))
        if not packages:
            self._dump("packages-empty", response.text)
            raise DnsError("Strato: keine Pakete in der Paketliste erkannt")
        return packages

    def locate(self, fqdn: str) -> tuple[str, str, str]:
        """Findet (cID, vhost, prefix) für einen FQDN: vhost = bei Strato verwaltete Domain."""
        fqdn = fqdn.rstrip(".").lower()
        labels = fqdn.split(".")
        packages = self.list_packages()
        # Vom längsten Kandidaten (mind. 2 Labels) absteigend suchen
        for i in range(1, len(labels) - 1):
            candidate = ".".join(labels[i:])
            for cid, text in packages:
                if re.search(rf"(^|\s){re.escape(candidate)}(\s|$)", text) or candidate in text.split():
                    prefix = ".".join(labels[:i])
                    return cid, candidate, prefix
        # Fallback: Second-Level-Domain wie im Originalprojekt, Paket über Teilstring
        sld = ".".join(labels[-2:])
        for cid, text in packages:
            if sld in text:
                return cid, sld, ".".join(labels[:-2])
        raise DnsError(f"Strato: kein Paket enthält eine Domain für {fqdn}")

    # --- TXT-Records -------------------------------------------------------
    def get_txt_records(self, cid: str, vhost: str) -> list[TxtRecord]:
        response = self._get(
            {
                "sessionID": self.session_id,
                "cID": cid,
                "node": "ManageDomains",
                "action_show_txt_records": "",
                "vhost": vhost,
            }
        )
        soup = BeautifulSoup(response.text, "html.parser")
        records: list[TxtRecord] = []
        templates = soup.select("div.txt-record-tmpl")
        if not templates and soup.select_one("form") is None:
            self._dump("records", response.text)
            raise DnsError("Strato: TXT-Record-Seite nicht erkannt")
        for tmpl in templates:
            prefix_el = tmpl.select_one("input[name='prefix']")
            type_el = tmpl.select_one("select[name='type']")
            value_el = tmpl.select_one("textarea[name='value']")
            if prefix_el is None or value_el is None:
                continue
            rtype = "TXT"
            if type_el is not None:
                selected = type_el.select_one("option[selected]")
                if selected is not None and selected.get("value"):
                    rtype = selected["value"]
                else:
                    first = type_el.select_one("option")
                    if first is not None and first.get("value"):
                        rtype = first["value"]
            records.append(
                TxtRecord(prefix=prefix_el.get("value", ""), type=rtype, value=value_el.get_text().strip())
            )
        return records

    def push_txt_records(self, cid: str, vhost: str, records: list[TxtRecord]) -> None:
        response = self._post(
            {
                "sessionID": self.session_id,
                "cID": cid,
                "node": "ManageDomains",
                "vhost": vhost,
                "action_change_txt_records": "Einstellung+übernehmen",
                "prefix": [r.prefix for r in records],
                "type": [r.type for r in records],
                "value": [r.value for r in records],
            }
        )
        if response.status_code >= 400:
            self._dump("push", response.text)
            raise DnsError(f"Strato: Speichern der TXT-Records fehlgeschlagen (HTTP {response.status_code})")
        log.info("Strato: %d Records für %s gespeichert", len(records), vhost)


class StratoDns:
    def __init__(self, name: str, cfg: StratoProvider, debug_dir: Path | None = None):
        self.name = name
        self.cfg = cfg
        self.debug_dir = debug_dir
        self.username = env_secret(cfg.username_env, what=f"dns_providers.{name}.username_env")
        self.password = env_secret(cfg.password_env, what=f"dns_providers.{name}.password_env")
        self.totp_secret = env_secret(cfg.totp_secret_env, required=False, what=f"dns_providers.{name}.totp_secret_env")

    def client(self) -> StratoClient:
        c = StratoClient(
            api_url=self.cfg.api_url,
            username=self.username,
            password=self.password,
            totp_secret=self.totp_secret,
            totp_devicename=self.cfg.totp_devicename,
            debug_dir=self.debug_dir,
        )
        c.login()
        return c

    def add_txt(self, fqdn: str, value: str) -> None:
        c = self.client()
        cid, vhost, prefix = c.locate(fqdn)
        records = c.get_txt_records(cid, vhost)
        if any(r.prefix == prefix and r.type == "TXT" and r.value == value for r in records):
            log.info("Strato: TXT %s existiert bereits", fqdn)
            return
        records.append(TxtRecord(prefix=prefix, type="TXT", value=value))
        c.push_txt_records(cid, vhost, records)
        log.info("Strato: TXT %s gesetzt (Paket %s, vhost %s)", fqdn, cid, vhost)

    def remove_txt(self, fqdn: str, value: str) -> None:
        c = self.client()
        cid, vhost, prefix = c.locate(fqdn)
        records = c.get_txt_records(cid, vhost)
        kept = [r for r in records if not (r.prefix == prefix and r.type == "TXT" and r.value == value)]
        if len(kept) == len(records):
            log.info("Strato: TXT %s war nicht (mehr) vorhanden", fqdn)
            return
        c.push_txt_records(cid, vhost, kept)
        log.info("Strato: TXT %s entfernt", fqdn)

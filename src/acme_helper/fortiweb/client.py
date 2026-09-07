"""FortiWeb REST-API-Client (v2.0, FortiWeb 7.x/8.x).

Authentifizierung: Header "Authorization: <base64(JSON {username, password, vdom})>".
Alle Pfade sind über fortiwebs.<name>.endpoints überschreibbar, weil einzelne
Pfade zwischen Versionen abweichen können.
"""

from __future__ import annotations

import base64
import json
import logging
from typing import Any

import requests
import urllib3

from ..config import FortiWebConfig, env_secret
from ..errors import FortiWebError

log = logging.getLogger(__name__)

DEFAULT_ENDPOINTS: dict[str, str] = {
    # Lokale Server-Zertifikate
    "local_cert": "/api/v2.0/system/certificate.local",
    "local_cert_import": "/api/v2.0/system/certificate.local.import_certificate",
    "local_cert_json": "/api/v2.0/system/certificate.local.json_cert",
    # Intermediate-CA-Zertifikate und Gruppen (Pfad auf FortiWeb 8.0.7 bestätigt)
    "inter_cert": "/api/v2.0/system/certificate.intermediateca",
    "inter_cert_import": "/api/v2.0/system/certificate.intermediateca.import_certificate",
    "inter_group": "/api/v2.0/cmdb/system/certificate.intermediate-certificate-group",
    "inter_group_members": "/api/v2.0/cmdb/system/certificate.intermediate-certificate-group/members",
    # Server Policy und SNI
    "server_policy": "/api/v2.0/cmdb/server-policy/policy",
    "sni_group": "/api/v2.0/cmdb/system/certificate.sni",
    "sni_members": "/api/v2.0/cmdb/system/certificate.sni/members",
}

# Der Pfad für Intermediate-CA-Zertifikate ist nicht für jede Firmware belegt; diese Kandidaten werden
# beim ersten Zugriff der Reihe nach probiert (GET), der erste ohne Fehler wird verwendet.
INTER_CERT_CANDIDATES = [
    "/api/v2.0/system/certificate.intermediateca",
    "/api/v2.0/system/certificate.intermediate_ca",
    "/api/v2.0/system/certificate.intermediate-certificate",
    "/api/v2.0/system/certificate.intermediate",
    "/api/v2.0/system/certificate.intermediate-ca",
    "/api/v2.0/cmdb/system/certificate.intermediate-certificate",
    "/api/v2.0/cmdb/system/certificate.intermediate_ca",
]

# Felder, die FortiWeb bei GET mitliefert, aber bei PUT nicht akzeptiert
READONLY_KEYS = {"q_ref", "q_type", "can_view", "can_clone", "can_delete", "can_edit"}


def object_name(item: dict) -> str:
    for key in ("name", "_id", "mkey", "id"):
        if key in item and item[key] not in (None, ""):
            return str(item[key])
    raise FortiWebError(f"Objekt ohne Namen: {json.dumps(item)[:200]}")


def get_field(obj: dict, name: str, default: Any = None) -> Any:
    """Liest ein Feld tolerant gegenüber Bindestrich-/Unterstrich-Schreibweise."""
    for key in (name, name.replace("-", "_"), name.replace("_", "-")):
        if key in obj:
            return obj[key]
    return default


def set_field(obj: dict, name: str, value: Any) -> None:
    for key in (name, name.replace("-", "_"), name.replace("_", "-")):
        if key in obj:
            obj[key] = value
            return
    obj[name] = value


class FortiWebClient:
    def __init__(
        self,
        *,
        host: str,
        port: int,
        username: str,
        password: str,
        vdom: str = "root",
        verify: bool | str = True,
        timeout: int = 60,
        import_method: str = "multipart",
        body_wrapper: str = "data",
        endpoints: dict[str, str] | None = None,
        session: requests.Session | None = None,
    ):
        self.base_url = f"https://{host}:{port}"
        self.vdom = vdom
        self.timeout = timeout
        self.import_method = import_method
        self.body_wrapper = body_wrapper
        self.endpoints = {**DEFAULT_ENDPOINTS, **(endpoints or {})}
        # Explizit konfigurierte Intermediate-Pfade werden nicht überschrieben
        self._inter_cert_fixed = bool(endpoints and ("inter_cert" in endpoints or "inter_cert_import" in endpoints))
        self._inter_cert_discovered = self._inter_cert_fixed
        self._inter_cert_path: str | None = self.endpoints["inter_cert"] if self._inter_cert_fixed else None
        self.http = session or requests.Session()
        self.http.verify = verify
        if verify is False:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        token = base64.b64encode(
            json.dumps({"username": username, "password": password, "vdom": vdom}).encode()
        ).decode()
        self.http.headers.update({"Authorization": token, "Accept": "application/json"})

    @classmethod
    def from_config(cls, name: str, cfg: FortiWebConfig) -> "FortiWebClient":
        return cls(
            host=cfg.host,
            port=cfg.port,
            username=env_secret(cfg.username_env, what=f"fortiwebs.{name}.username_env"),
            password=env_secret(cfg.password_env, what=f"fortiwebs.{name}.password_env"),
            vdom=cfg.vdom,
            verify=cfg.verify_tls,
            timeout=cfg.timeout,
            import_method=cfg.import_method,
            body_wrapper=cfg.body_wrapper,
            endpoints=cfg.endpoints,
        )

    # --- HTTP-Basis --------------------------------------------------------
    def _url(self, key: str) -> str:
        return self.base_url + self.endpoints[key]

    def _request(self, method: str, key: str, *, params: dict | None = None, **kw) -> Any:
        url = self._url(key)
        try:
            resp = self.http.request(method, url, params=params, timeout=self.timeout, **kw)
        except requests.RequestException as exc:
            raise FortiWebError(f"FortiWeb {self.base_url} nicht erreichbar: {exc}") from exc
        body: Any = None
        text = resp.text or ""
        if text.strip():
            try:
                body = resp.json()
            except ValueError:
                body = None
        if resp.status_code >= 400:
            raise FortiWebError(
                f"FortiWeb {method} {self.endpoints[key]}"
                f"{'?' + '&'.join(f'{k}={v}' for k, v in (params or {}).items()) if params else ''}"
                f" -> HTTP {resp.status_code}: {text[:300]}"
            )
        if isinstance(body, dict):
            results = body.get("results", body)
            if isinstance(results, dict) and "errcode" in results and results.get("errcode") not in (0, None):
                raise FortiWebError(
                    f"FortiWeb {method} {self.endpoints[key]} Fehler {results.get('errcode')}: "
                    f"{results.get('message') or text[:300]}"
                )
            return results
        return body if body is not None else text

    def _wrap(self, data: dict) -> dict:
        return {"data": data} if self.body_wrapper == "data" else data

    def _get_one(self, key: str, mkey: str, extra: dict | None = None) -> dict | None:
        params = {"mkey": mkey, **(extra or {})}
        try:
            res = self._request("GET", key, params=params)
        except FortiWebError as exc:
            if "HTTP 404" in str(exc):
                return None
            raise
        if isinstance(res, list):
            for item in res:
                if isinstance(item, dict) and object_name(item) == mkey:
                    return item
            return None
        if isinstance(res, dict) and res:
            return res
        return None

    def _list(self, key: str, params: dict | None = None) -> list[dict]:
        res = self._request("GET", key, params=params)
        if isinstance(res, list):
            return [r for r in res if isinstance(r, dict)]
        if isinstance(res, dict):
            # Manche Endpunkte liefern {"name": {...}} oder ein einzelnes Objekt
            if all(isinstance(v, dict) for v in res.values()) and res:
                return [{"name": k, **v} for k, v in res.items()]
            return [res]
        return []

    def _clean_for_put(self, obj: dict) -> dict:
        return {k: v for k, v in obj.items() if k not in READONLY_KEYS}

    # --- Verbindungstest ---------------------------------------------------
    def ping(self) -> int:
        return len(self.list_local_certificates())

    def discover_intermediate_endpoint(self) -> str | None:
        """Probiert die Kandidaten für den Intermediate-CA-Pfad durch und merkt sich den ersten Treffer."""
        if self._inter_cert_discovered:
            return self._inter_cert_path
        self._inter_cert_discovered = True
        tried: list[str] = []
        for path in [self.endpoints["inter_cert"], *INTER_CERT_CANDIDATES]:
            if path in tried:
                continue
            tried.append(path)
            url = self.base_url + path
            try:
                resp = self.http.get(url, timeout=self.timeout)
            except requests.RequestException as exc:
                raise FortiWebError(f"FortiWeb {self.base_url} nicht erreichbar: {exc}") from exc
            body_ok = True
            try:
                body = resp.json()
                results = body.get("results", body) if isinstance(body, dict) else body
                if isinstance(results, dict) and results.get("errcode") not in (None, 0):
                    body_ok = False
            except ValueError:
                body_ok = False
            if resp.status_code < 400 and body_ok:
                self.endpoints["inter_cert"] = path
                self.endpoints["inter_cert_import"] = path + ".import_certificate"
                self._inter_cert_path = path
                log.info("FortiWeb: Intermediate-CA-Endpunkt gefunden: %s", path)
                return path
            log.debug("Intermediate-Kandidat %s: HTTP %s", path, resp.status_code)
        log.warning("FortiWeb: kein Intermediate-CA-Endpunkt gefunden (probiert: %s)", ", ".join(tried))
        return None

    def probe_endpoints(self) -> dict[str, str]:
        """GET auf alle Listen-Endpunkte; liefert {key: 'ok'|Fehlertext}."""
        out: dict[str, str] = {}
        found = self.discover_intermediate_endpoint()
        for key in ("local_cert", "inter_cert", "inter_group", "server_policy", "sni_group"):
            if key == "inter_cert" and found is None:
                out[key] = (
                    "kein Pfad gefunden (probiert: " + ", ".join(INTER_CERT_CANDIDATES) + "). "
                    "Pfad aus dem FortiWeb-GUI (Browser-Entwicklertools) unter endpoints.inter_cert eintragen "
                    "oder chain_mode=fullchain nutzen."
                )
                continue
            try:
                self._request("GET", key)
                out[key] = "ok" + (f" ({self.endpoints[key]})" if key == "inter_cert" else "")
            except FortiWebError as exc:
                out[key] = str(exc)[:200]
        return out

    # --- Lokale Zertifikate ------------------------------------------------
    def list_local_certificates(self) -> list[str]:
        return [object_name(i) for i in self._list("local_cert")]

    def import_local_certificate(self, name: str, cert_pem: str, key_pem: str) -> str:
        """Lädt Zertifikat + Key hoch und gibt den Namen zurück, unter dem FortiWeb es führt."""
        if self.import_method == "json":
            res = self._request(
                "POST",
                "local_cert_json",
                json=self._wrap({"name": name, "certificate": cert_pem, "private-key": key_pem}),
            )
        else:
            files = {
                "certificateFile": (f"{name}", cert_pem.encode(), "application/x-pem-file"),
                "keyFile": (f"{name}.key", key_pem.encode(), "application/x-pem-file"),
            }
            data = {"type": "certificate", "hsm": "undefined", "password": "undefined"}
            res = self._request("POST", "local_cert_import", files=files, data=data)
        effective = name
        if isinstance(res, dict):
            for key in ("_id", "name", "mkey"):
                if res.get(key):
                    effective = str(res[key])
                    break
        if effective not in self.list_local_certificates():
            # Manche Versionen hängen die Dateiendung an oder schneiden sie ab
            candidates = [c for c in self.list_local_certificates() if c.startswith(name) or name.startswith(c)]
            if len(candidates) == 1:
                effective = candidates[0]
            else:
                raise FortiWebError(
                    f"Zertifikat '{name}' nach Upload nicht in der Liste gefunden (Antwort: {str(res)[:200]})"
                )
        log.info("FortiWeb: Zertifikat '%s' hochgeladen", effective)
        return effective

    def delete_local_certificate(self, name: str) -> None:
        self._request("DELETE", "local_cert", params={"mkey": name})
        log.info("FortiWeb: Zertifikat '%s' gelöscht", name)

    # --- Intermediate CA ---------------------------------------------------
    def _ensure_intermediate_endpoint(self) -> None:
        if self.discover_intermediate_endpoint() is None:
            raise FortiWebError(
                "Intermediate-CA-Endpunkt auf dieser Firmware nicht gefunden. Entweder den Pfad unter "
                "fortiwebs.<name>.endpoints.inter_cert konfigurieren oder chain_mode auf 'fullchain' bzw. 'none' "
                "stellen (Unraid: CERT1_CHAIN_MODE=fullchain)."
            )

    def list_intermediate_certificates(self) -> list[str]:
        self._ensure_intermediate_endpoint()
        return [object_name(i) for i in self._list("inter_cert")]

    def import_intermediate_certificate(self, name: str, pem: str) -> str:
        self._ensure_intermediate_endpoint()
        files = {"uploadedFile": (name, pem.encode(), "application/x-pem-file")}
        res = self._request("POST", "inter_cert_import", files=files, data={"type": "localPC"})
        effective = name
        if isinstance(res, dict):
            for key in ("_id", "name", "mkey"):
                if res.get(key):
                    effective = str(res[key])
                    break
        existing = self.list_intermediate_certificates()
        if effective not in existing:
            candidates = [c for c in existing if c.startswith(name) or name.startswith(c)]
            if len(candidates) == 1:
                effective = candidates[0]
            else:
                raise FortiWebError(f"Intermediate '{name}' nach Upload nicht gefunden")
        log.info("FortiWeb: Intermediate-CA '%s' hochgeladen", effective)
        return effective

    def delete_intermediate_certificate(self, name: str) -> None:
        self._request("DELETE", "inter_cert", params={"mkey": name})

    def get_intermediate_group(self, name: str) -> dict | None:
        return self._get_one("inter_group", name)

    def create_intermediate_group(self, name: str) -> None:
        self._request("POST", "inter_group", json=self._wrap({"name": name}))
        log.info("FortiWeb: Intermediate-CA-Gruppe '%s' angelegt", name)

    def list_intermediate_group_members(self, group: str) -> list[dict]:
        return self._list("inter_group_members", params={"mkey": group})

    def add_intermediate_group_member(self, group: str, cert_name: str) -> None:
        self._request("POST", "inter_group_members", params={"mkey": group}, json=self._wrap({"name": cert_name}))
        log.info("FortiWeb: '%s' zur Intermediate-Gruppe '%s' hinzugefügt", cert_name, group)

    def delete_intermediate_group_member(self, group: str, member_id: str) -> None:
        self._request("DELETE", "inter_group_members", params={"mkey": group, "sub_mkey": member_id})

    # --- Server Policy -----------------------------------------------------
    def get_server_policy(self, name: str) -> dict | None:
        return self._get_one("server_policy", name)

    def update_server_policy(self, name: str, changes: dict) -> dict:
        current = self.get_server_policy(name)
        if current is None:
            raise FortiWebError(f"Server Policy '{name}' existiert nicht")
        updated = self._clean_for_put(dict(current))
        for k, v in changes.items():
            set_field(updated, k, v)
        self._request("PUT", "server_policy", params={"mkey": name}, json=self._wrap(updated))
        log.info("FortiWeb: Server Policy '%s' aktualisiert (%s)", name, ", ".join(changes))
        return updated

    # --- SNI ---------------------------------------------------------------
    def get_sni_group(self, name: str) -> dict | None:
        return self._get_one("sni_group", name)

    def list_sni_members(self, group: str) -> list[dict]:
        members = self._list("sni_members", params={"mkey": group})
        if members:
            return members
        grp = self.get_sni_group(group)
        if grp and isinstance(get_field(grp, "members"), list):
            return get_field(grp, "members")
        return []

    def update_sni_member(self, group: str, member: dict, changes: dict) -> None:
        member_id = str(get_field(member, "id") or get_field(member, "_id") or get_field(member, "name"))
        updated = self._clean_for_put(dict(member))
        for k, v in changes.items():
            set_field(updated, k, v)
        self._request(
            "PUT", "sni_members", params={"mkey": group, "sub_mkey": member_id}, json=self._wrap(updated)
        )
        log.info("FortiWeb: SNI-Member %s/%s aktualisiert", group, member_id)

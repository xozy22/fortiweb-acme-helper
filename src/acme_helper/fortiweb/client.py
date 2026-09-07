"""FortiWeb REST-API-Client (v2.0, FortiWeb 7.x/8.x).

Authentifizierung: Header "Authorization: <base64(JSON {username, password, vdom})>".

Pfade und Body-Formate stammen aus der FortiWeb-8.0-"Configuration API"-Referenz (Swagger, basePath
/api/v2.0/cmdb). Dort sind Intermediate-Zertifikate, Gruppen und SNI-Gruppen normale cmdb-Objekte:
Anlegen per POST mit {"data": {...}}, Untertabellen (members) liegen im Objekt und werden per PUT des
ganzen Objekts geändert. Nur der Upload lokaler Zertifikate nutzt den multipart-Endpunkt aus dem
Fortinet-Community-Tip, weil dieser auf 8.0.7 nachweislich funktioniert.
Alle Pfade sind über fortiwebs.<name>.endpoints überschreibbar.
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
    # Lokale Server-Zertifikate: Liste/Löschen/JSON-Anlage (cmdb), Upload (multipart)
    "local_cert": "/api/v2.0/cmdb/system/certificate.local",
    "local_cert_import": "/api/v2.0/system/certificate.local.import_certificate",
    # Intermediate-Zertifikate: Liste/Löschen (cmdb), Upload (multipart, auf 8.0.7 geprüft; die FortiWeb
    # vergibt den Namen selbst, z.B. Inter_Cert_1), Gruppen (cmdb, members im Objekt)
    "inter_cert": "/api/v2.0/cmdb/system/certificate.intermediate-certificate",
    "inter_cert_import": "/api/v2.0/system/certificate.intermediateca",
    "inter_group": "/api/v2.0/cmdb/system/certificate.intermediate-certificate-group",
    # Untertabellen: GET/POST ?mkey=<gruppe>, DELETE/PUT zusätzlich &sub_mkey=<id> (auf 8.0.7 geprüft)
    "inter_group_members": "/api/v2.0/cmdb/system/certificate.intermediate-certificate-group/members",
    # Server Policy und SNI (cmdb)
    "server_policy": "/api/v2.0/cmdb/server-policy/policy",
    "sni_group": "/api/v2.0/cmdb/system/certificate.sni",
    "sni_members": "/api/v2.0/cmdb/system/certificate.sni/members",
}

# Felder, die FortiWeb bei GET mitliefert, aber bei PUT nicht gehören: Berechtigungs-/Referenzzähler,
# "*_val"-Spiegelfelder, Objekt-Id und Untertabellen-Zähler (auf 8.0.7 mit einem No-op-PUT geprüft)
READONLY_KEYS = {"q_ref", "q_type", "can_view", "can_clone", "can_delete", "can_edit"}
TOPLEVEL_READONLY_KEYS = READONLY_KEYS | {"id", "sz_members"}


def _strip(obj: dict, drop: set[str]) -> dict:
    return {k: v for k, v in obj.items() if k not in drop and not k.endswith("_val")}


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


def member_id(member: dict) -> str:
    return str(get_field(member, "id") or get_field(member, "_id") or get_field(member, "name") or "")


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
        errcode: int | None = None
        results: Any = body.get("results", body) if isinstance(body, dict) else None
        if isinstance(results, dict) and results.get("errcode") not in (0, None, "0"):
            try:
                errcode = int(results["errcode"])
            except (TypeError, ValueError):
                errcode = None
        if resp.status_code >= 400:
            raise FortiWebError(
                f"FortiWeb {method} {self.endpoints[key]}"
                f"{'?' + '&'.join(f'{k}={v}' for k, v in (params or {}).items()) if params else ''}"
                f" -> HTTP {resp.status_code}: {text[:300]}",
                status=resp.status_code,
                errcode=errcode,
            )
        if isinstance(body, dict):
            if errcode is not None:
                raise FortiWebError(
                    f"FortiWeb {method} {self.endpoints[key]} Fehler {errcode}: "
                    f"{results.get('message') or text[:300]}",
                    status=resp.status_code,
                    errcode=errcode,
                )
            return results
        return body if body is not None else text

    def _wrap(self, data: dict) -> dict:
        return {"data": data} if self.body_wrapper == "data" else data

    def _get_one(self, key: str, mkey: str) -> dict | None:
        try:
            res = self._request("GET", key, params={"mkey": mkey})
        except FortiWebError as exc:
            if exc.not_found:
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
            if res and all(isinstance(v, dict) for v in res.values()):
                return [{"name": k, **v} for k, v in res.items()]
            return [res]
        return []

    def _clean_for_put(self, obj: dict) -> dict:
        out = _strip(obj, TOPLEVEL_READONLY_KEYS)
        for key, value in list(out.items()):
            if isinstance(value, list) and value and all(isinstance(m, dict) for m in value):
                out[key] = [_strip(m, READONLY_KEYS) for m in value]  # Member behalten ihre id
        return out

    def _put_object(self, key: str, name: str, obj: dict) -> None:
        self._request("PUT", key, params={"mkey": name}, json=self._wrap(self._clean_for_put(obj)))

    # --- Verbindungstest ---------------------------------------------------
    def ping(self) -> int:
        return len(self.list_local_certificates())

    def probe_endpoints(self) -> dict[str, str]:
        """GET auf alle Listen-Endpunkte; liefert {key: 'ok'|Fehlertext}."""
        out: dict[str, str] = {}
        for key in ("local_cert", "inter_cert", "inter_group", "server_policy", "sni_group"):
            try:
                self._request("GET", key)
                out[key] = "ok"
            except FortiWebError as exc:
                out[key] = str(exc)[:200]
        return out

    # --- Lokale Zertifikate ------------------------------------------------
    def list_local_certificates(self) -> list[str]:
        return [object_name(i) for i in self._list("local_cert")]

    def import_local_certificate(self, name: str, cert_pem: str, key_pem: str) -> str:
        """Lädt Zertifikat + Key hoch und gibt den Namen zurück, unter dem FortiWeb es führt."""
        if self.import_method == "json":
            # cmdb-Anlage laut Referenz: name, type, certificate, private-key
            res = self._request(
                "POST",
                "local_cert",
                json=self._wrap(
                    {"name": name, "type": "certificate", "certificate": cert_pem, "private-key": key_pem}
                ),
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
        existing = self.list_local_certificates()
        if effective not in existing:
            # Manche Versionen hängen die Dateiendung an oder schneiden sie ab
            candidates = [c for c in existing if c.startswith(name) or name.startswith(c)]
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
    def list_intermediate_certificates(self) -> list[str]:
        return [object_name(i) for i in self._list("inter_cert")]

    def import_intermediate_certificate(self, name: str, pem: str) -> str:
        """Lädt ein Intermediate-Zertifikat hoch und gibt den Namen zurück, den die FortiWeb vergeben hat.

        Auf 8.0.7 ignoriert die FortiWeb den Dateinamen und nummeriert selbst (Inter_Cert_1, ...).
        Der cmdb-POST mit PEM-Text aus der Referenz wird mit "This certificate is invalid" abgelehnt.
        """
        before = set(self.list_intermediate_certificates())
        files = {"uploadedFile": (name, pem.encode(), "application/x-pem-file")}
        res = self._request("POST", "inter_cert_import", files=files, data={"type": "localPC"})
        effective: str | None = None
        if isinstance(res, dict):
            for key in ("_id", "name", "mkey"):
                if res.get(key):
                    effective = str(res[key])
                    break
        after = set(self.list_intermediate_certificates())
        if effective is None or effective not in after:
            new = after - before
            if len(new) == 1:
                effective = next(iter(new))
            else:
                raise FortiWebError(
                    f"Intermediate-Upload: Antwort {str(res)[:120]}, aber kein eindeutiges neues Objekt in der Liste "
                    f"(neu: {sorted(new) or '-'})"
                )
        log.info("FortiWeb: Intermediate-CA hochgeladen als '%s'", effective)
        return effective

    def delete_intermediate_certificate(self, name: str) -> None:
        self._request("DELETE", "inter_cert", params={"mkey": name})

    def get_intermediate_group(self, name: str) -> dict | None:
        return self._get_one("inter_group", name)

    def create_intermediate_group(self, name: str, members: list[str] | None = None) -> None:
        data: dict = {"name": name}
        if members:
            data["members"] = [{"id": i, "name": m} for i, m in enumerate(members, start=1)]
        self._request("POST", "inter_group", json=self._wrap(data))
        log.info("FortiWeb: Intermediate-CA-Gruppe '%s' angelegt", name)

    def list_intermediate_group_members(self, group: str) -> list[dict]:
        return self._list("inter_group_members", params={"mkey": group})

    def add_intermediate_group_member(self, group: str, cert_name: str) -> None:
        if any(str(get_field(m, "name", "")) == cert_name for m in self.list_intermediate_group_members(group)):
            return
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
        updated = dict(current)
        for k, v in changes.items():
            set_field(updated, k, v)
        self._put_object("server_policy", name, updated)
        log.info("FortiWeb: Server Policy '%s' aktualisiert (%s)", name, ", ".join(changes))
        return updated

    # --- SNI ---------------------------------------------------------------
    def get_sni_group(self, name: str) -> dict | None:
        return self._get_one("sni_group", name)

    def list_sni_members(self, group: str) -> list[dict]:
        return self._list("sni_members", params={"mkey": group})

    def update_sni_member(self, group: str, member: dict, changes: dict) -> None:
        """Ändert einen SNI-Member über die Untertabelle (PUT ?mkey=<gruppe>&sub_mkey=<id>)."""
        target = member_id(member)
        updated = dict(member)
        for k, v in changes.items():
            set_field(updated, k, v)
        self._request(
            "PUT",
            "sni_members",
            params={"mkey": group, "sub_mkey": target},
            json=self._wrap(_strip(updated, READONLY_KEYS | {"seq", "_id"})),
        )
        log.info("FortiWeb: SNI-Member %s/%s aktualisiert", group, target)

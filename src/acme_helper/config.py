"""Konfigurationsmodelle (YAML + Secrets aus Env)."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Annotated, Literal, Union

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator

from .errors import ConfigError

DEFAULT_CONFIG_PATH = "/config/config.yaml"
DEFAULT_DATA_DIR = "/data"


def env_secret(var_name: str | None, *, required: bool = True, what: str = "") -> str | None:
    """Liest ein Secret aus der Umgebung. Fehlt es, gibt es einen klaren Fehler."""
    if not var_name:
        if required:
            raise ConfigError(f"Keine Env-Variable konfiguriert für {what}")
        return None
    value = os.environ.get(var_name)
    if value is None or value == "":
        if required:
            raise ConfigError(f"Env-Variable {var_name} ({what}) ist nicht gesetzt")
        return None
    return value.strip()


class AcmeConfig(BaseModel):
    email: str
    staging: bool = False
    directory_url: str | None = None  # Überschreibt Let's Encrypt (z.B. andere CA)
    key_type: Literal["ecdsa", "rsa"] = "ecdsa"
    propagation_timeout: int = 300  # Sekunden, bis TXT auf allen autoritativen NS sichtbar sein muss
    propagation_interval: int = 10
    eab_kid_env: str | None = None  # External Account Binding (nur für andere CAs)
    eab_hmac_env: str | None = None


class CloudflareProvider(BaseModel):
    type: Literal["cloudflare"]
    api_token_env: str
    api_url: str = "https://api.cloudflare.com/client/v4"
    ttl: int = 60


class DodeProvider(BaseModel):
    type: Literal["dode"]
    token_env: str
    api_url: str = "https://my.do.de/api/letsencrypt"


class StratoProvider(BaseModel):
    type: Literal["strato"]
    username_env: str
    password_env: str
    totp_secret_env: str | None = None
    totp_devicename: str | None = None
    api_url: str = "https://www.strato.de/apps/CustomerService"
    propagation_timeout: int = 900  # Strato publiziert langsam


DnsProviderConfig = Annotated[
    Union[CloudflareProvider, DodeProvider, StratoProvider], Field(discriminator="type")
]


class ZoneConfig(BaseModel):
    suffix: str
    provider: str

    @field_validator("suffix")
    @classmethod
    def _norm(cls, v: str) -> str:
        return v.strip().rstrip(".").lower()


class FortiWebConfig(BaseModel):
    host: str
    port: int = 8443
    username_env: str
    password_env: str
    vdom: str = "root"
    verify_tls: bool | str = True  # False oder Pfad zu CA-Bundle
    timeout: int = 60
    import_method: Literal["multipart", "json"] = "multipart"
    body_wrapper: Literal["data", "none"] = "data"  # {"data": {...}} bei PUT/POST auf cmdb
    endpoints: dict[str, str] = Field(default_factory=dict)  # Überschreibt Standard-Pfade


class SniBinding(BaseModel):
    """Mehrere Domains in einer Policy: SNI-Gruppe mit einem Member je Domain.

    Die Gruppe und fehlende Member werden angelegt (create), bestehende Member, deren Domain zu einem
    Muster passt, werden auf das neue Zertifikat umgestellt. In den Policies (policies, Default:
    server_policies des Ziels) wird SNI aktiviert und die Gruppe eingetragen.
    """

    group: str
    domains: list[str] = Field(default_factory=list)  # leer = Domains des Zertifikats
    create: bool = True  # Gruppe und fehlende Member anlegen
    policies: list[str] | None = None  # None = server_policies des Deploy-Ziels; [] = keine Policy anfassen
    strict: bool | None = None  # sni-strict in der Policy setzen (None = unverändert)
    wildcard: Literal["plain", "regex"] = "plain"  # *.example.com als plain-Domain oder als Regex-Member


class DeployTarget(BaseModel):
    fortiweb: str
    cert_name_prefix: str
    chain_mode: Literal["intermediate-group", "fullchain", "none"] = "intermediate-group"
    intermediate_group: str | None = None  # Default: <prefix>-chain
    server_policies: list[str] = Field(default_factory=list)
    bind_default_certificate: bool = True  # Feld "certificate" der Policies setzen (Default-Zertifikat ohne SNI)
    sni: list[SniBinding] = Field(default_factory=list)
    keep_old: int = 1

    @field_validator("cert_name_prefix")
    @classmethod
    def _prefix(cls, v: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,40}", v):
            raise ValueError("cert_name_prefix: nur A-Z a-z 0-9 _ . - und max. 40 Zeichen")
        return v


class CertificateConfig(BaseModel):
    name: str
    domains: list[str]
    key_type: Literal["ecdsa", "rsa"] | None = None
    deploy: list[DeployTarget] = Field(default_factory=list)

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", v):
            raise ValueError("certificate.name darf nur A-Z a-z 0-9 _ . - enthalten")
        return v

    @field_validator("domains")
    @classmethod
    def _domains(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("mindestens eine Domain nötig")
        out = []
        for raw in v:
            d = raw.strip().rstrip(".").lower()
            if not re.fullmatch(r"(\*\.)?([a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9-]{2,}", d):
                hint = " (Wildcard heißt '*.domain.tld', mit Punkt nach dem Stern)" if "*" in d else ""
                raise ValueError(f"'{raw}' ist keine gültige Domain{hint}")
            out.append(d)
        return out


class ScheduleConfig(BaseModel):
    time: str = "03:30"
    timezone: str = "Europe/Berlin"

    @field_validator("time", mode="before")
    @classmethod
    def _time(cls, v) -> str:
        if isinstance(v, int):  # YAML liest unquotiertes 03:30 als Sexagesimalzahl 210
            v = f"{v // 60:02d}:{v % 60:02d}"
        v = str(v).strip()
        if not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", v):
            raise ValueError("schedule.time muss HH:MM sein (in YAML in Anführungszeichen setzen)")
        return v


class NotifyConfig(BaseModel):
    webhook_url_env: str | None = None
    on_success: bool = True
    on_failure: bool = True


class Config(BaseModel):
    acme: AcmeConfig
    dns_providers: dict[str, DnsProviderConfig] = Field(default_factory=dict)
    zones: list[ZoneConfig] = Field(default_factory=list)
    fortiwebs: dict[str, FortiWebConfig] = Field(default_factory=dict)
    certificates: list[CertificateConfig] = Field(default_factory=list)
    schedule: ScheduleConfig = Field(default_factory=ScheduleConfig)
    notify: NotifyConfig = Field(default_factory=NotifyConfig)
    data_dir: str = DEFAULT_DATA_DIR
    source: str = Field(default="", exclude=True)  # Herkunft (Datei oder Env), nur informativ

    @model_validator(mode="after")
    def _cross_check(self) -> "Config":
        for z in self.zones:
            if z.provider not in self.dns_providers:
                raise ValueError(f"zones: Provider '{z.provider}' für '{z.suffix}' ist nicht definiert")
        names = [c.name for c in self.certificates]
        if len(names) != len(set(names)):
            raise ValueError("certificates: Namen müssen eindeutig sein")
        seen_prefix: set[tuple[str, str]] = set()
        for c in self.certificates:
            for t in c.deploy:
                if t.fortiweb not in self.fortiwebs:
                    raise ValueError(f"certificate '{c.name}': FortiWeb '{t.fortiweb}' ist nicht definiert")
                key = (t.fortiweb, t.cert_name_prefix)
                if key in seen_prefix:
                    raise ValueError(
                        f"cert_name_prefix '{t.cert_name_prefix}' auf '{t.fortiweb}' wird mehrfach verwendet"
                    )
                seen_prefix.add(key)
        return self

    @property
    def data_path(self) -> Path:
        return Path(self.data_dir)

    @property
    def letsencrypt_dir(self) -> Path:
        return self.data_path / "letsencrypt"

    @property
    def state_dir(self) -> Path:
        return self.data_path / "state"

    @property
    def debug_dir(self) -> Path:
        return self.data_path / "debug"

    def certificate(self, name: str) -> CertificateConfig:
        for c in self.certificates:
            if c.name == name:
                return c
        raise ConfigError(f"Zertifikat '{name}' ist nicht konfiguriert")


def config_path_from_env(explicit: str | None = None) -> Path:
    return Path(explicit or os.environ.get("ACME_HELPER_CONFIG") or DEFAULT_CONFIG_PATH)


# --- Env-only-Modus (Unraid, Portainer, plain docker run) --------------------
ENV_MODE_TRIGGER = "ACME_EMAIL"


def _split(value: str | None, seps: str = ",;") -> list[str]:
    if not value:
        return []
    for s in seps[1:]:
        value = value.replace(s, seps[0])
    return [v.strip() for v in value.split(seps[0]) if v.strip()]


def _bool(value: str | None, default: bool = False) -> bool:
    if value is None or value.strip() == "":
        return default
    return value.strip().lower() in ("1", "true", "yes", "on", "ja")


def _prefix_from_domain(domain: str) -> str:
    d = domain.lower().removeprefix("*.")
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", d).replace(".", "-").strip("-")
    return ("wc-" + slug)[:40].rstrip("-")


def _parse_sni(value: str | None, *, policies: str | None = None, strict: str | None = None,
               wildcard: str | None = None, create: str | None = None) -> list[dict]:
    """'sni-main:*.example.com|example.com;sni-other' -> [{group, domains, ...}]"""
    out: list[dict] = []
    for entry in _split(value, ";"):
        group, _, patterns = entry.partition(":")
        item: dict = {"group": group.strip(), "domains": _split(patterns, "|,")}
        if policies is not None:
            item["policies"] = _split(policies)
        if strict is not None and strict.strip() != "":
            item["strict"] = _bool(strict)
        if wildcard:
            item["wildcard"] = wildcard.strip().lower()
        if create is not None and create.strip() != "":
            item["create"] = _bool(create, True)
        out.append(item)
    return out


def _parse_zones(value: str | None) -> list[dict]:
    """'example.com=cf;acme.example.net=dode' -> [{suffix, provider}]"""
    out: list[dict] = []
    for entry in _split(value, ",; \n"):
        suffix, sep, provider = re.split(r"([=:])", entry, maxsplit=1) if re.search(r"[=:]", entry) else (entry, "", "")
        if not sep:
            raise ConfigError(f"ZONES: Eintrag '{entry}' braucht die Form suffix=provider")
        out.append({"suffix": suffix.strip(), "provider": provider.strip()})
    return out


def config_from_env(env: Mapping[str, str] | None = None) -> dict:
    """Baut die YAML-Struktur aus Umgebungsvariablen. Secrets bleiben in der Umgebung,
    die Struktur enthält nur die Variablennamen."""
    e: Mapping[str, str] = env if env is not None else os.environ
    if not e.get(ENV_MODE_TRIGGER):
        raise ConfigError(f"Env-Modus braucht mindestens {ENV_MODE_TRIGGER}")

    raw: dict = {
        "acme": {
            "email": e[ENV_MODE_TRIGGER].strip(),
            "staging": _bool(e.get("ACME_STAGING"), False),
            "key_type": (e.get("ACME_KEY_TYPE") or "ecdsa").strip().lower(),
            "propagation_timeout": int(e.get("ACME_PROPAGATION_TIMEOUT") or 300),
        }
    }
    if e.get("ACME_DIRECTORY_URL"):
        raw["acme"]["directory_url"] = e["ACME_DIRECTORY_URL"].strip()

    providers: dict[str, dict] = {}
    if e.get("CF_API_TOKEN"):
        providers["cf"] = {"type": "cloudflare", "api_token_env": "CF_API_TOKEN"}
    if e.get("DODE_TOKEN"):
        providers["dode"] = {"type": "dode", "token_env": "DODE_TOKEN"}
    if e.get("STRATO_USER"):
        providers["strato"] = {
            "type": "strato",
            "username_env": "STRATO_USER",
            "password_env": "STRATO_PASS",
            "totp_secret_env": "STRATO_TOTP_SECRET" if e.get("STRATO_TOTP_SECRET") else None,
            "totp_devicename": (e.get("STRATO_TOTP_DEVICENAME") or "").strip() or None,
        }
        if e.get("STRATO_API_URL"):
            providers["strato"]["api_url"] = e["STRATO_API_URL"].strip()
    raw["dns_providers"] = providers

    fortiwebs: dict[str, dict] = {}
    if e.get("FW_HOST"):
        verify_raw = (e.get("FW_VERIFY_TLS") or "true").strip()
        verify: bool | str = verify_raw if "/" in verify_raw else _bool(verify_raw, True)
        fortiwebs["fw1"] = {
            "host": e["FW_HOST"].strip(),
            "port": int(e.get("FW_PORT") or 8443),
            "username_env": "FW_USER",
            "password_env": "FW_PASS",
            "vdom": (e.get("FW_VDOM") or "root").strip(),
            "verify_tls": verify,
            "import_method": (e.get("FW_IMPORT_METHOD") or "multipart").strip(),
            "body_wrapper": (e.get("FW_BODY_WRAPPER") or "data").strip(),
        }
    raw["fortiwebs"] = fortiwebs

    certs: list[dict] = []
    n = 1
    while True:
        def get(key: str) -> str | None:
            val = e.get(f"CERT{n}_{key}")
            if val is None and n == 1:
                val = e.get(f"CERT_{key}")
            return val.strip() if val and val.strip() else None

        domains = _split(get("DOMAINS"), ", ")
        if not domains:
            break
        prefix = get("PREFIX") or _prefix_from_domain(domains[0])
        cert: dict = {"name": get("NAME") or prefix, "domains": domains, "deploy": []}
        if get("KEY_TYPE"):
            cert["key_type"] = get("KEY_TYPE").lower()
        if fortiwebs:
            cert["deploy"].append(
                {
                    "fortiweb": "fw1",
                    "cert_name_prefix": prefix,
                    "chain_mode": get("CHAIN_MODE") or "intermediate-group",
                    "server_policies": _split(get("POLICIES")),
                    "bind_default_certificate": _bool(get("BIND_DEFAULT"), True),
                    "sni": _parse_sni(
                        get("SNI"),
                        policies=get("SNI_POLICIES"),
                        strict=get("SNI_STRICT"),
                        wildcard=get("SNI_WILDCARD"),
                        create=get("SNI_CREATE"),
                    ),
                    "keep_old": int(get("KEEP_OLD") or 1),
                }
            )
        certs.append(cert)
        n += 1
    raw["certificates"] = certs

    zones = _parse_zones(e.get("ZONES"))
    if not zones and len(providers) == 1:
        # Genau ein Provider: alle Domains gehören dorthin
        only = next(iter(providers))
        seen: set[str] = set()
        for c in certs:
            for d in c["domains"]:
                suffix = d.removeprefix("*.")
                if suffix not in seen:
                    seen.add(suffix)
                    zones.append({"suffix": suffix, "provider": only})
    raw["zones"] = zones

    raw["schedule"] = {
        "time": (e.get("SCHEDULE_TIME") or "03:30").strip(),
        "timezone": (e.get("TZ") or e.get("SCHEDULE_TIMEZONE") or "Europe/Berlin").strip(),
    }
    raw["notify"] = {
        "webhook_url_env": "NOTIFY_WEBHOOK" if e.get("NOTIFY_WEBHOOK") else None,
        "on_success": _bool(e.get("NOTIFY_ON_SUCCESS"), True),
        "on_failure": _bool(e.get("NOTIFY_ON_FAILURE"), True),
    }
    return raw


def load_config(path: str | Path | None = None) -> Config:
    p = config_path_from_env(str(path) if path else None)
    if p.is_file():
        source = str(p)
        try:
            raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise ConfigError(f"YAML-Fehler in {p}: {exc}") from exc
    elif os.environ.get(ENV_MODE_TRIGGER):
        source = "Umgebungsvariablen"
        raw = config_from_env()
    else:
        raise ConfigError(
            f"Konfigurationsdatei nicht gefunden: {p}. Entweder die Datei anlegen oder den Env-Modus nutzen "
            f"(mindestens {ENV_MODE_TRIGGER}, CERT1_DOMAINS und einen DNS-Provider setzen)."
        )
    if "data_dir" not in raw and os.environ.get("ACME_HELPER_DATA"):
        raw["data_dir"] = os.environ["ACME_HELPER_DATA"]
    try:
        cfg = Config.model_validate(raw)
    except Exception as exc:  # pydantic.ValidationError
        raise ConfigError(f"Ungültige Konfiguration aus {source}:\n{exc}") from exc
    cfg.source = source
    return cfg

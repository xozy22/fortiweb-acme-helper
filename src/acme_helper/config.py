"""Konfigurationsmodelle (YAML + Secrets aus Env)."""

from __future__ import annotations

import os
import re
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
    group: str
    domains: list[str] = Field(default_factory=list)  # leer = alle Member der Gruppe


class DeployTarget(BaseModel):
    fortiweb: str
    cert_name_prefix: str
    chain_mode: Literal["intermediate-group", "fullchain", "none"] = "intermediate-group"
    intermediate_group: str | None = None  # Default: <prefix>-chain
    server_policies: list[str] = Field(default_factory=list)
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
        return [d.strip().rstrip(".").lower() for d in v]


class ScheduleConfig(BaseModel):
    time: str = "03:30"
    timezone: str = "Europe/Berlin"

    @field_validator("time")
    @classmethod
    def _time(cls, v: str) -> str:
        if not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", v):
            raise ValueError("schedule.time muss HH:MM sein")
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


def load_config(path: str | Path | None = None) -> Config:
    p = config_path_from_env(str(path) if path else None)
    if not p.is_file():
        raise ConfigError(f"Konfigurationsdatei nicht gefunden: {p}")
    try:
        raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"YAML-Fehler in {p}: {exc}") from exc
    if "data_dir" not in raw and os.environ.get("ACME_HELPER_DATA"):
        raw["data_dir"] = os.environ["ACME_HELPER_DATA"]
    try:
        return Config.model_validate(raw)
    except Exception as exc:  # pydantic.ValidationError
        raise ConfigError(f"Ungültige Konfiguration in {p}:\n{exc}") from exc

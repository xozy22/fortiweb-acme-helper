from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from acme_helper.config import Config

BASE_CONFIG = {
    "acme": {"email": "test@example.com", "staging": True},
    "dns_providers": {
        "cf": {"type": "cloudflare", "api_token_env": "CF_API_TOKEN"},
        "dode": {"type": "dode", "token_env": "DODE_TOKEN"},
        "strato": {"type": "strato", "username_env": "STRATO_USER", "password_env": "STRATO_PASS"},
    },
    "zones": [
        {"suffix": "example.com", "provider": "cf"},
        {"suffix": "acme.example.net", "provider": "dode"},
        {"suffix": "legacy-strato.de", "provider": "strato"},
    ],
    "fortiwebs": {
        "fw1": {"host": "fw.test", "port": 8443, "username_env": "FW_USER", "password_env": "FW_PASS", "verify_tls": False}
    },
    "certificates": [
        {
            "name": "wc-example",
            "domains": ["example.com", "*.example.com"],
            "deploy": [
                {
                    "fortiweb": "fw1",
                    "cert_name_prefix": "wc-example",
                    "server_policies": ["pol1"],
                    "sni": [{"group": "sni1", "domains": ["*.example.com"]}],
                }
            ],
        }
    ],
}


@pytest.fixture
def env(monkeypatch):
    for k, v in {
        "CF_API_TOKEN": "cf-token",
        "DODE_TOKEN": "dode-token",
        "STRATO_USER": "12345",
        "STRATO_PASS": "geheim",
        "FW_USER": "admin",
        "FW_PASS": "pw",
    }.items():
        monkeypatch.setenv(k, v)


@pytest.fixture
def cfg(tmp_path: Path, env) -> Config:
    data = dict(BASE_CONFIG)
    data["data_dir"] = str(tmp_path / "data")
    return Config.model_validate(data)


def make_cert(cn: str, issuer_name: str | None = None, *, days: int = 90) -> tuple[str, str]:
    """Selbstsigniertes Zertifikat + Key als PEM."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name or cn)])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(days=days))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()
    return cert_pem, key_pem


@pytest.fixture
def lineage(cfg: Config) -> Path:
    """Legt eine certbot-artige Lineage unter <data>/letsencrypt/live/wc-example an."""
    live = cfg.letsencrypt_dir / "live" / "wc-example"
    live.mkdir(parents=True)
    leaf, key = make_cert("*.example.com", "Fake LE Intermediate")
    inter, _ = make_cert("Fake LE Intermediate", "Fake LE Root")
    (live / "cert.pem").write_text(leaf)
    (live / "privkey.pem").write_text(key)
    (live / "chain.pem").write_text(inter)
    (live / "fullchain.pem").write_text(leaf + inter)
    return live

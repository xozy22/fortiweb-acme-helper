import pytest
import yaml

from acme_helper.config import Config, config_from_env, load_config
from acme_helper.errors import ConfigError

ENV = {
    "ACME_EMAIL": "admin@example.com",
    "ACME_STAGING": "true",
    "CF_API_TOKEN": "secret-cf-token",
    "DODE_TOKEN": "secret-dode-token",
    "STRATO_USER": "123",
    "STRATO_PASS": "secret-strato-pw",
    "STRATO_TOTP_SECRET": "secret-totp",
    "STRATO_TOTP_DEVICENAME": "acme",
    "ZONES": "example.com=cf; acme.example.net=dode, legacy-strato.de:strato",
    "FW_HOST": "10.0.0.5",
    "FW_PORT": "443",
    "FW_USER": "admin",
    "FW_PASS": "pw",
    "FW_VERIFY_TLS": "false",
    "CERT1_DOMAINS": "example.com, *.example.com",
    "CERT1_POLICIES": "policy-web,policy-api",
    "CERT1_SNI": "sni-main:*.example.com|example.com;sni-other",
    "CERT2_DOMAINS": "*.legacy-strato.de",
    "CERT2_PREFIX": "wc-strato",
    "CERT2_CHAIN_MODE": "fullchain",
    "CERT2_KEEP_OLD": "2",
    "TZ": "Europe/Vienna",
    "SCHEDULE_TIME": "04:15",
    "NOTIFY_WEBHOOK": "https://hooks.example/x",
}


def test_full_env_config():
    raw = config_from_env(ENV)
    cfg = Config.model_validate(raw)
    assert cfg.acme.staging is True
    assert set(cfg.dns_providers) == {"cf", "dode", "strato"}
    assert cfg.dns_providers["strato"].totp_secret_env == "STRATO_TOTP_SECRET"
    assert [(z.suffix, z.provider) for z in cfg.zones] == [
        ("example.com", "cf"), ("acme.example.net", "dode"), ("legacy-strato.de", "strato")]
    fw = cfg.fortiwebs["fw1"]
    assert fw.port == 443 and fw.verify_tls is False and fw.username_env == "FW_USER"

    c1, c2 = cfg.certificates
    assert c1.name == "wc-example-com" and c1.domains == ["example.com", "*.example.com"]
    t1 = c1.deploy[0]
    assert t1.cert_name_prefix == "wc-example-com"
    assert t1.server_policies == ["policy-web", "policy-api"]
    assert [(s.group, s.domains) for s in t1.sni] == [("sni-main", ["*.example.com", "example.com"]), ("sni-other", [])]
    t2 = c2.deploy[0]
    assert c2.name == "wc-strato" and t2.chain_mode == "fullchain" and t2.keep_old == 2

    assert cfg.schedule.time == "04:15" and cfg.schedule.timezone == "Europe/Vienna"
    assert cfg.notify.webhook_url_env == "NOTIFY_WEBHOOK"
    # Die Struktur enthält keine Secret-Werte
    dumped = yaml.safe_dump(raw)
    assert "secret-" not in dumped


def test_single_provider_derives_zones():
    env = {"ACME_EMAIL": "a@b.c", "CF_API_TOKEN": "x", "CERT_DOMAINS": "*.foo.de,foo.de,bar.foo.de"}
    cfg = Config.model_validate(config_from_env(env))
    assert [(z.suffix, z.provider) for z in cfg.zones] == [("foo.de", "cf"), ("bar.foo.de", "cf")]
    assert cfg.certificates[0].deploy == []  # kein FW_HOST -> nur Zertifikat holen


def test_verify_tls_path():
    env = {**ENV, "FW_VERIFY_TLS": "/config/ca.pem"}
    assert config_from_env(env)["fortiwebs"]["fw1"]["verify_tls"] == "/config/ca.pem"


def test_bad_zone_entry():
    with pytest.raises(ConfigError, match="ZONES"):
        config_from_env({**ENV, "ZONES": "example.com"})


def test_load_config_falls_back_to_env(monkeypatch, tmp_path):
    for k, v in ENV.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setenv("ACME_HELPER_DATA", str(tmp_path))
    cfg = load_config(tmp_path / "missing.yaml")
    assert cfg.source == "Umgebungsvariablen"
    assert cfg.data_dir == str(tmp_path)


def test_load_config_error_without_env(monkeypatch, tmp_path):
    monkeypatch.delenv("ACME_EMAIL", raising=False)
    with pytest.raises(ConfigError, match="Env-Modus"):
        load_config(tmp_path / "missing.yaml")

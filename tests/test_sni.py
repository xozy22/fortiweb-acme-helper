"""SNI: mehrere Domains in einer Policy. Gruppe und Member werden angelegt, Policy bekommt SNI."""

import copy

import pytest

from acme_helper.config import Config, SniBinding, config_from_env
from acme_helper.errors import FortiWebError
from acme_helper.fortiweb.deploy import deploy_certificate, sni_member_spec, wildcard_regex
from acme_helper.state import DeployState
from tests.conftest import BASE_CONFIG
from tests.test_deploy import FakeFortiWeb


def _cfg(tmp_path, env, **sni_overrides):
    data = copy.deepcopy(BASE_CONFIG)
    data["data_dir"] = str(tmp_path / "data")
    target = data["certificates"][0]["deploy"][0]
    target["sni"] = [{"group": "neu-sni", **sni_overrides}]
    return Config.model_validate(data)


def test_sni_group_and_members_created(cfg, lineage, tmp_path, env):
    cfg = _cfg(tmp_path, env)  # domains leer -> Domains des Zertifikats
    fw = FakeFortiWeb()
    res = deploy_certificate(cfg, cfg.certificates[0], cfg.certificates[0].deploy[0], state=DeployState(cfg.state_dir), client=fw)
    members = fw.sni["neu-sni"]
    assert [(m["domain"], m["domain-type"]) for m in members] == [("example.com", "plain"), ("*.example.com", "plain")]
    assert all(m["local-cert"] == res.fw_cert_name and m["inter-group"] == "wc-example-chain" for m in members)
    pol = fw.policies["pol1"]
    assert pol["sni"] == "enable" and pol["sni-certificate"] == "neu-sni"
    assert pol["certificate"] == res.fw_cert_name  # Default-Zertifikat weiterhin gesetzt
    assert any("angelegt" in m for m in res.messages)


def test_second_run_is_idempotent(cfg, lineage, tmp_path, env):
    cfg = _cfg(tmp_path, env)
    fw = FakeFortiWeb()
    state = DeployState(cfg.state_dir)
    deploy_certificate(cfg, cfg.certificates[0], cfg.certificates[0].deploy[0], state=state, client=fw)
    deploy_certificate(cfg, cfg.certificates[0], cfg.certificates[0].deploy[0], state=state, client=fw, force=True)
    assert len(fw.sni["neu-sni"]) == 2  # keine Duplikate


def test_wildcard_regex_mode(cfg, lineage, tmp_path, env):
    cfg = _cfg(tmp_path, env, wildcard="regex", domains=["*.example.com"])
    fw = FakeFortiWeb()
    deploy_certificate(cfg, cfg.certificates[0], cfg.certificates[0].deploy[0], state=DeployState(cfg.state_dir), client=fw)
    m = fw.sni["neu-sni"][0]
    assert m["domain-type"] == "regular" and m["domain"] == r"^[^.]+\.example\.com$"
    assert wildcard_regex("*.a-b.de") == r"^[^.]+\.a\-b\.de$" or wildcard_regex("*.a-b.de") == r"^[^.]+\.a-b\.de$"
    assert sni_member_spec("www.example.com", "regex") == ("www.example.com", "plain")


def test_no_default_certificate_and_explicit_policies(cfg, lineage, tmp_path, env):
    data = copy.deepcopy(BASE_CONFIG)
    data["data_dir"] = str(tmp_path / "data")
    target = data["certificates"][0]["deploy"][0]
    target["bind_default_certificate"] = False
    target["server_policies"] = []
    target["sni"] = [{"group": "sni1", "domains": ["*.example.com"], "policies": ["pol1"], "strict": True}]
    cfg = Config.model_validate(data)
    fw = FakeFortiWeb()
    res = deploy_certificate(cfg, cfg.certificates[0], cfg.certificates[0].deploy[0], state=DeployState(cfg.state_dir), client=fw)
    assert fw.policies["pol1"]["certificate"] == "wc-example-20260401"  # unverändert
    assert fw.policies["pol1"]["sni"] == "enable" and fw.policies["pol1"]["sni-certificate"] == "sni1"
    assert fw.policies["pol1"]["sni-strict"] == "enable"
    assert fw.sni["sni1"][0]["local-cert"] == res.fw_cert_name


def test_create_false_raises_for_missing_group(cfg, lineage, tmp_path, env):
    cfg = _cfg(tmp_path, env, create=False)
    with pytest.raises(FortiWebError, match="create: false"):
        deploy_certificate(cfg, cfg.certificates[0], cfg.certificates[0].deploy[0], state=DeployState(cfg.state_dir), client=FakeFortiWeb())


def test_env_sni_options():
    env = {
        "ACME_EMAIL": "a@b.c", "CF_API_TOKEN": "x", "FW_HOST": "h", "FW_USER": "u", "FW_PASS": "p",
        "CERT1_DOMAINS": "example.com,*.example.com", "CERT1_POLICIES": "pol-a",
        "CERT1_SNI": "sni-main;sni-extra:foo.example.com", "CERT1_SNI_POLICIES": "pol-a,pol-b",
        "CERT1_SNI_STRICT": "true", "CERT1_SNI_WILDCARD": "regex", "CERT1_BIND_DEFAULT": "false",
    }
    cfg = Config.model_validate(config_from_env(env))
    t = cfg.certificates[0].deploy[0]
    assert t.bind_default_certificate is False
    assert [s.group for s in t.sni] == ["sni-main", "sni-extra"]
    assert t.sni[0].domains == [] and t.sni[1].domains == ["foo.example.com"]
    assert t.sni[0].policies == ["pol-a", "pol-b"] and t.sni[0].strict is True and t.sni[0].wildcard == "regex"
    assert SniBinding(group="g").policies is None

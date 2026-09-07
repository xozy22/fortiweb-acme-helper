import copy

import pytest
import responses

from acme_helper.config import Config
from acme_helper.dns.strato import StratoClient
from acme_helper.errors import FortiWebError
from acme_helper.fortiweb.client import FortiWebClient
from tests.conftest import BASE_CONFIG

BASE = "https://fw.test:8443"


@pytest.mark.parametrize("bad", ["*kobiolka.com", "kobiolka", "*.", "foo..de", "-x.de"])
def test_invalid_domains_are_rejected(bad):
    data = copy.deepcopy(BASE_CONFIG)
    data["certificates"][0]["domains"] = [bad]
    with pytest.raises(ValueError, match="keine gültige Domain"):
        Config.model_validate(data)


def test_wildcard_hint_mentions_dot():
    data = copy.deepcopy(BASE_CONFIG)
    data["certificates"][0]["domains"] = ["*kobiolka.com"]
    with pytest.raises(ValueError, match=r"\*\.domain\.tld"):
        Config.model_validate(data)


def test_valid_domains_pass():
    data = copy.deepcopy(BASE_CONFIG)
    data["certificates"][0]["domains"] = ["*.Kobiolka.com.", "sub.kobiolka.com", "kobiolka.com"]
    cfg = Config.model_validate(data)
    assert cfg.certificates[0].domains == ["*.kobiolka.com", "sub.kobiolka.com", "kobiolka.com"]


def test_strato_page_hints():
    html = """<html><head><title>STRATO Kunden-Login</title></head><body>
    <h1>Login</h1><div class="form-error">Benutzername oder Passwort falsch.</div>
    <input name="identifier"><input name="passwd"><img src="captcha.png"></body></html>"""
    hints = StratoClient.page_hints(html)
    assert any("Kunden-Login" in h for h in hints)
    assert any("Passwort falsch" in h for h in hints)
    assert any("Captcha" in h for h in hints)
    assert any("identifier" in h for h in hints)


@responses.activate
def test_intermediate_endpoint_discovery():
    err = {"results": {"errcode": "-20001", "message": "The REST API has invalid URL."}}
    responses.get(f"{BASE}/api/v2.0/system/certificate.intermediate_ca", json=err, status=500)
    responses.get(f"{BASE}/api/v2.0/system/certificate.intermediate-certificate",
                  json={"results": [{"name": "le-abc"}]})
    client = FortiWebClient(host="fw.test", port=8443, username="a", password="b", verify=False)
    assert client.discover_intermediate_endpoint() == "/api/v2.0/system/certificate.intermediate-certificate"
    assert client.endpoints["inter_cert_import"].endswith("certificate.intermediate-certificate.import_certificate")
    assert client.list_intermediate_certificates() == ["le-abc"]
    # zweiter Aufruf nutzt den gemerkten Pfad, kein erneutes Probieren
    assert client.discover_intermediate_endpoint() == "/api/v2.0/system/certificate.intermediate-certificate"


@responses.activate
def test_intermediate_discovery_all_fail():
    err = {"results": {"errcode": "-20001", "message": "invalid URL"}}
    for path in ("/api/v2.0/system/certificate.intermediate_ca", "/api/v2.0/system/certificate.intermediate-certificate",
                 "/api/v2.0/system/certificate.intermediate", "/api/v2.0/system/certificate.intermediate-ca",
                 "/api/v2.0/system/certificate.intermediateca", "/api/v2.0/cmdb/system/certificate.intermediate-certificate",
                 "/api/v2.0/cmdb/system/certificate.intermediate_ca"):
        responses.get(f"{BASE}{path}", json=err, status=500)
    client = FortiWebClient(host="fw.test", port=8443, username="a", password="b", verify=False)
    assert client.discover_intermediate_endpoint() is None
    with pytest.raises(FortiWebError, match="chain_mode"):
        client.list_intermediate_certificates()
    assert "kein Pfad gefunden" in client.probe_endpoints()["inter_cert"]


@responses.activate
def test_explicit_endpoint_is_not_overridden():
    responses.get(f"{BASE}/custom/inter", json={"results": []})
    client = FortiWebClient(host="fw.test", port=8443, username="a", password="b", verify=False,
                            endpoints={"inter_cert": "/custom/inter"})
    assert client.discover_intermediate_endpoint() == "/custom/inter"
    assert client.list_intermediate_certificates() == []

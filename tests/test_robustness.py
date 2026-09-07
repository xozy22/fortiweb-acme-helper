import copy
import json

import pytest
import responses

from acme_helper.config import Config
from acme_helper.dns.strato import StratoClient
from acme_helper.errors import FortiWebError
from acme_helper.fortiweb.client import FortiWebClient
from tests.conftest import BASE_CONFIG

BASE = "https://fw.test:8443"
INTER = f"{BASE}/api/v2.0/cmdb/system/certificate.intermediate-certificate"
GROUP = f"{BASE}/api/v2.0/cmdb/system/certificate.intermediate-certificate-group"
SNI = f"{BASE}/api/v2.0/cmdb/system/certificate.sni"


def _client(**kw):
    return FortiWebClient(host="fw.test", port=8443, username="a", password="b", verify=False, **kw)


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


# --- Intermediate-CA laut FortiWeb-8.0-Referenz: cmdb-Objekt mit data.name / data.certificate ---
@responses.activate
def test_intermediate_created_as_cmdb_object():
    listed = {"names": []}
    responses.add_callback(
        responses.GET, INTER,
        callback=lambda r: (200, {}, json.dumps({"results": [{"name": n} for n in listed["names"]]})),
    )

    def create(req):
        body = json.loads(req.body)
        assert body["data"]["name"] == "le-1234" and body["data"]["certificate"].startswith("-----BEGIN")
        listed["names"].append("le-1234")
        return 200, {}, '{"results": {"errcode": 0}}'

    responses.add_callback(responses.POST, INTER, callback=create)
    assert _client().import_intermediate_certificate("le-1234", "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----") == "le-1234"


@responses.activate
def test_intermediate_create_not_listed_is_error():
    responses.get(INTER, json={"results": []})
    responses.post(INTER, json={"results": {"errcode": 0}})
    with pytest.raises(FortiWebError, match="taucht aber nicht in der Liste"):
        _client().import_intermediate_certificate("le-1", "PEM")


@responses.activate
def test_group_member_added_via_put_of_whole_object():
    group = {"name": "grp", "members": [{"id": 1, "name": "le-old", "q_ref": 1}], "q_ref": 2, "can_view": 1}
    responses.get(GROUP, json={"results": group}, match=[responses.matchers.query_param_matcher({"mkey": "grp"})])
    put = responses.put(GROUP, json={"results": {"errcode": 0}}, match=[responses.matchers.query_param_matcher({"mkey": "grp"})])
    _client().add_intermediate_group_member("grp", "le-new")
    sent = json.loads(put.calls[0].request.body)["data"]
    assert sent["name"] == "grp" and "q_ref" not in sent and "can_view" not in sent
    assert sent["members"] == [{"id": 1, "name": "le-old"}, {"id": 2, "name": "le-new"}]


@responses.activate
def test_group_member_already_present_no_put():
    responses.get(GROUP, json={"results": {"name": "grp", "members": [{"id": 1, "name": "le-x"}]}})
    _client().add_intermediate_group_member("grp", "le-x")
    assert all(c.request.method == "GET" for c in responses.calls)


@responses.activate
def test_create_group_with_members():
    post = responses.post(GROUP, json={"results": {"errcode": 0}})
    _client().create_intermediate_group("grp", ["a", "b"])
    assert json.loads(post.calls[0].request.body)["data"]["members"] == [{"id": 1, "name": "a"}, {"id": 2, "name": "b"}]


@responses.activate
def test_sni_member_updated_via_put_of_whole_group():
    grp = {"name": "sni1", "members": [
        {"id": 1, "domain": "*.example.com", "local-cert": "old", "certificate-type": "disable"},
        {"id": 2, "domain": "other.org", "local-cert": "y"},
    ]}
    responses.get(SNI, json={"results": grp})
    put = responses.put(SNI, json={"results": {"errcode": 0}})
    c = _client()
    members = c.list_sni_members("sni1")
    c.update_sni_member("sni1", members[0], {"local-cert": "new", "inter-group": "chain"})
    sent = json.loads(put.calls[0].request.body)["data"]
    assert sent["members"][0]["local-cert"] == "new" and sent["members"][0]["inter-group"] == "chain"
    assert sent["members"][1]["local-cert"] == "y"


@responses.activate
def test_explicit_endpoint_override_for_intermediate():
    responses.get(f"{BASE}/custom/inter", json={"results": [{"name": "x"}]})
    assert _client(endpoints={"inter_cert": "/custom/inter"}).list_intermediate_certificates() == ["x"]

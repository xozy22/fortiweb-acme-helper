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
INTER_UP = f"{BASE}/api/v2.0/system/certificate.intermediateca"
GROUP = f"{BASE}/api/v2.0/cmdb/system/certificate.intermediate-certificate-group"
SNI = f"{BASE}/api/v2.0/cmdb/system/certificate.sni"
POLICY = f"{BASE}/api/v2.0/cmdb/server-policy/policy"


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


# --- Intermediate-CA: multipart-Upload, FortiWeb vergibt den Namen (auf 8.0.7 geprüft) ---
@responses.activate
def test_intermediate_upload_returns_assigned_name():
    listed = {"names": ["Inter_Cert_1"]}
    responses.add_callback(
        responses.GET, INTER,
        callback=lambda r: (200, {}, json.dumps({"results": [{"name": n} for n in listed["names"]]})),
    )

    def upload(req):
        body = req.body if isinstance(req.body, bytes) else req.body.encode()
        assert b'name="uploadedFile"' in body and b'name="type"' in body and b"localPC" in body
        listed["names"].append("Inter_Cert_2")
        return 200, {}, '{ "_id": "Inter_Cert_2" }'

    responses.add_callback(responses.POST, INTER_UP, callback=upload)
    assert _client().import_intermediate_certificate("le-1234", "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----") == "Inter_Cert_2"


@responses.activate
def test_intermediate_upload_without_id_uses_list_diff():
    listed = {"names": []}
    responses.add_callback(responses.GET, INTER, callback=lambda r: (200, {}, json.dumps({"results": [{"name": n} for n in listed["names"]]})))

    def upload(req):
        listed["names"].append("Inter_Cert_7")
        return 200, {}, "ok"

    responses.add_callback(responses.POST, INTER_UP, callback=upload)
    assert _client().import_intermediate_certificate("x", "PEM") == "Inter_Cert_7"


@responses.activate
def test_intermediate_upload_nothing_new_is_error():
    responses.get(INTER, json={"results": []})
    responses.post(INTER_UP, body="ok")
    with pytest.raises(FortiWebError, match="kein eindeutiges neues Objekt"):
        _client().import_intermediate_certificate("x", "PEM")


GROUP_MEMBERS = GROUP + "/members"
SNI_MEMBERS = SNI + "/members"


@responses.activate
def test_group_member_added_via_subtable_post():
    # Antwortformat der Untertabelle wie auf 8.0.7 beobachtet
    responses.get(GROUP_MEMBERS, json={"results": [{"seq": 1, "_id": 1, "q_type": 0, "id": "1", "name": "Inter_Cert_1", "name_val": "1722"}]},
                  match=[responses.matchers.query_param_matcher({"mkey": "grp"})])
    post = responses.post(GROUP_MEMBERS, json={"results": {"q_type": 0, "id": "2", "name": "Inter_Cert_2"}},
                          match=[responses.matchers.query_param_matcher({"mkey": "grp"})])
    _client().add_intermediate_group_member("grp", "Inter_Cert_2")
    assert json.loads(post.calls[0].request.body) == {"data": {"name": "Inter_Cert_2"}}


@responses.activate
def test_group_member_already_present_no_post():
    responses.get(GROUP_MEMBERS, json={"results": [{"id": "1", "name": "Inter_Cert_1"}]})
    _client().add_intermediate_group_member("grp", "Inter_Cert_1")
    assert all(c.request.method == "GET" for c in responses.calls)


@responses.activate
def test_group_member_delete_uses_sub_mkey():
    d = responses.delete(GROUP_MEMBERS, json={"results": {"status": "success"}},
                         match=[responses.matchers.query_param_matcher({"mkey": "grp", "sub_mkey": "1"})])
    _client().delete_intermediate_group_member("grp", "1")
    assert d.call_count == 1


@responses.activate
def test_policy_put_strips_val_id_and_counters():
    pol = {"id": 1, "can_view": 0, "q_ref": 0, "can_clone": 1, "q_type": 1, "name": "pol", "ssl": "enable", "ssl_val": "1",
           "certificate": "", "certificate_val": "", "certificate-type": "enable", "certificate-type_val": "1", "sz_members": 0}
    responses.get(POLICY, json={"results": pol})
    put = responses.put(POLICY, json={"results": {"errcode": 0}})
    _client().update_server_policy("pol", {"certificate": "new", "certificate-type": "disable"})
    sent = json.loads(put.calls[0].request.body)["data"]
    assert sent == {"name": "pol", "ssl": "enable", "certificate": "new", "certificate-type": "disable"}


@responses.activate
def test_sni_member_updated_via_subtable_put():
    members = [
        {"seq": 1, "_id": 1, "q_type": 0, "id": "1", "domain": "*.example.com", "local-cert": "old", "local-cert_val": "old", "certificate-type": "disable"},
        {"seq": 2, "_id": 2, "id": "2", "domain": "other.org", "local-cert": "y"},
    ]
    responses.get(SNI_MEMBERS, json={"results": members}, match=[responses.matchers.query_param_matcher({"mkey": "sni1"})])
    put = responses.put(SNI_MEMBERS, json={"results": {"errcode": 0}},
                        match=[responses.matchers.query_param_matcher({"mkey": "sni1", "sub_mkey": "1"})])
    c = _client()
    got = c.list_sni_members("sni1")
    c.update_sni_member("sni1", got[0], {"local-cert": "new", "inter-group": "chain"})
    sent = json.loads(put.calls[0].request.body)["data"]
    assert sent == {"id": "1", "domain": "*.example.com", "local-cert": "new", "certificate-type": "disable", "inter-group": "chain"}


@responses.activate
def test_explicit_endpoint_override_for_intermediate():
    responses.get(f"{BASE}/custom/inter", json={"results": [{"name": "x"}]})
    assert _client(endpoints={"inter_cert": "/custom/inter"}).list_intermediate_certificates() == ["x"]

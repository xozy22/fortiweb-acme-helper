import base64
import json

import pytest
import responses

from acme_helper.errors import FortiWebError
from acme_helper.fortiweb.client import FortiWebClient

BASE = "https://fw.test:8443"


def _client(**kw):
    return FortiWebClient(host="fw.test", port=8443, username="admin", password="pw", verify=False, **kw)


LOCAL = f"{BASE}/api/v2.0/cmdb/system/certificate.local"


@responses.activate
def test_auth_header_is_base64_json():
    responses.get(LOCAL, json={"results": [{"name": "a"}, {"_id": "b"}]})
    assert _client().list_local_certificates() == ["a", "b"]
    token = responses.calls[0].request.headers["Authorization"]
    assert json.loads(base64.b64decode(token)) == {"username": "admin", "password": "pw", "vdom": "root"}


@responses.activate
def test_import_multipart_returns_effective_name():
    responses.post(f"{BASE}/api/v2.0/system/certificate.local.import_certificate", json={"results": {"_id": "wc-20260907"}})
    responses.get(LOCAL, json={"results": [{"name": "wc-20260907"}]})
    name = _client().import_local_certificate("wc-20260907", "CERT", "KEY")
    assert name == "wc-20260907"
    body = responses.calls[0].request.body
    assert b'name="type"' in body and b"certificate" in body
    assert b'filename="wc-20260907"' in body


@responses.activate
def test_update_server_policy_get_modify_put():
    url = f"{BASE}/api/v2.0/cmdb/server-policy/policy"
    policy = {"name": "pol1", "certificate": "old", "ssl": "enable", "q_ref": 3, "can_view": 1}
    responses.get(url, json={"results": policy}, match=[responses.matchers.query_param_matcher({"mkey": "pol1"})])
    put = responses.put(url, json={"results": {"errcode": 0}}, match=[responses.matchers.query_param_matcher({"mkey": "pol1"})])
    _client().update_server_policy("pol1", {"certificate": "new", "intermediate-certificate-group": "grp"})
    sent = json.loads(put.calls[0].request.body)
    assert sent["data"]["certificate"] == "new"
    assert sent["data"]["ssl"] == "enable"
    assert sent["data"]["intermediate-certificate-group"] == "grp"
    assert "q_ref" not in sent["data"] and "can_view" not in sent["data"]


@responses.activate
def test_body_wrapper_none():
    url = f"{BASE}/api/v2.0/cmdb/server-policy/policy"
    responses.get(url, json={"results": {"name": "pol1", "certificate": "old"}})
    put = responses.put(url, json={})
    _client(body_wrapper="none").update_server_policy("pol1", {"certificate": "new"})
    assert json.loads(put.calls[0].request.body) == {"name": "pol1", "certificate": "new"}


@responses.activate
def test_import_json_uses_cmdb_create():
    post = responses.post(LOCAL, json={"results": {"errcode": 0}})
    responses.get(LOCAL, json={"results": [{"name": "wc-1"}]})
    assert _client(import_method="json").import_local_certificate("wc-1", "CERT", "KEY") == "wc-1"
    sent = json.loads(post.calls[0].request.body)["data"]
    assert sent == {"name": "wc-1", "type": "certificate", "certificate": "CERT", "private-key": "KEY"}


@responses.activate
def test_delete_uses_cmdb_mkey():
    d = responses.delete(LOCAL, json={"results": {"errcode": 0}}, match=[responses.matchers.query_param_matcher({"mkey": "wc-1"})])
    _client().delete_local_certificate("wc-1")
    assert d.call_count == 1


@responses.activate
def test_http_error_raises():
    responses.get(LOCAL, status=401, body="unauthorized")
    with pytest.raises(FortiWebError, match="HTTP 401"):
        _client().list_local_certificates()


@responses.activate
def test_errcode_raises():
    responses.get(LOCAL, json={"results": {"errcode": -5, "message": "nope"}})
    with pytest.raises(FortiWebError, match="nope"):
        _client().list_local_certificates()


@responses.activate
def test_endpoint_override():
    responses.get(f"{BASE}/custom/path", json={"results": []})
    assert _client(endpoints={"local_cert": "/custom/path"}).list_local_certificates() == []

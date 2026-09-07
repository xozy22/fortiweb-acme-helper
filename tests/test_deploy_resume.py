"""Deploy setzt nach einem Fehler beim Binden fort, ohne das Leaf erneut hochzuladen."""

import pytest
import responses

from acme_helper.errors import FortiWebError
from acme_helper.fortiweb.client import FortiWebClient
from acme_helper.fortiweb.deploy import deploy_certificate
from acme_helper.state import DeployState
from tests.test_deploy import FakeFortiWeb

BASE = "https://fw.test:8443"


def test_resume_after_failed_binding(cfg, lineage):
    fw = FakeFortiWeb()
    initial = set(fw.local)
    state = DeployState(cfg.state_dir)
    cert, target = cfg.certificates[0], cfg.certificates[0].deploy[0]

    # Erster Versuch: Intermediate-Upload scheitert (wie auf 8.0.7 beobachtet)
    def boom(name, pem):
        raise FortiWebError("Response ended prematurely")

    fw.import_intermediate_certificate = boom
    with pytest.raises(FortiWebError):
        deploy_certificate(cfg, cert, target, state=state, client=fw)
    uploaded = [n for n in fw.local if n not in initial]
    assert len(uploaded) == 1
    assert state.get("wc-example", "fw1")["phase"] == "uploaded"

    # Zweiter Versuch: Intermediate klappt jetzt; das Leaf wird NICHT erneut hochgeladen
    fw.import_intermediate_certificate = lambda name, pem: fw.inter.append(name) or name
    res = deploy_certificate(cfg, cert, target, state=state, client=fw)
    assert res.changed and res.fw_cert_name == uploaded[0]
    assert [n for n in fw.local if n not in initial] == uploaded
    assert any("bereits hochgeladen" in m for m in res.messages)
    assert state.get("wc-example", "fw1")["phase"] == "bound"

    # Dritter Versuch: unverändert
    assert not deploy_certificate(cfg, cert, target, state=state, client=fw).changed


@responses.activate
def test_intermediate_import_tries_variants():
    list_url = f"{BASE}/api/v2.0/system/certificate.intermediateca"
    imp = f"{BASE}/api/v2.0/system/certificate.intermediateca.import_certificate"
    seen: list[str] = []
    listed = {"names": []}

    def list_cb(_req):
        return 200, {}, '{"results": [' + ",".join(f'{{"name":"{n}"}}' for n in listed["names"]) + "]}"

    def import_cb(req):
        body = req.body if isinstance(req.body, bytes) else req.body.encode()
        if b'name="uploadedFile"' in body:
            seen.append("uploadedFile")
            return 500, {}, "closed"
        seen.append("certificateFile")
        listed["names"].append("le-1234")
        return 200, {}, '{"results": {"_id": "le-1234"}}'

    responses.add_callback(responses.GET, list_url, callback=list_cb)
    responses.add_callback(responses.POST, imp, callback=import_cb)
    client = FortiWebClient(host="fw.test", port=8443, username="a", password="b", verify=False)
    assert client.import_intermediate_certificate("le-1234", "PEM") == "le-1234"
    assert seen == ["uploadedFile", "certificateFile"]
    # Zweiter Upload nutzt direkt die gemerkte Variante
    listed["names"].append("le-5678")
    client.import_intermediate_certificate("le-5678", "PEM")
    assert seen[-1] == "certificateFile" and seen.count("uploadedFile") == 1


@responses.activate
def test_intermediate_import_all_variants_fail():
    list_url = f"{BASE}/api/v2.0/system/certificate.intermediateca"
    imp = f"{BASE}/api/v2.0/system/certificate.intermediateca.import_certificate"
    responses.get(list_url, json={"results": []})
    responses.post(imp, status=500, body="closed")
    client = FortiWebClient(host="fw.test", port=8443, username="a", password="b", verify=False)
    with pytest.raises(FortiWebError, match="CERT1_CHAIN_MODE=fullchain"):
        client.import_intermediate_certificate("le-1", "PEM")

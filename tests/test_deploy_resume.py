"""Deploy setzt nach einem Fehler beim Binden fort, ohne das Leaf erneut hochzuladen."""

import pytest

from acme_helper.errors import FortiWebError
from acme_helper.fortiweb.deploy import deploy_certificate
from acme_helper.state import DeployState
from tests.test_deploy import FakeFortiWeb


def test_resume_after_failed_binding(cfg, lineage):
    fw = FakeFortiWeb()
    initial = set(fw.local)
    state = DeployState(cfg.state_dir)
    cert, target = cfg.certificates[0], cfg.certificates[0].deploy[0]

    # Erster Versuch: Intermediate-Anlage scheitert
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

"""Wechsel der Kette (z.B. Staging -> Produktion): Gruppe wird auf die aktuelle Kette gebracht,
nicht mehr benötigte, selbst hochgeladene Intermediates werden gelöscht."""

from acme_helper.fortiweb.deploy import deploy_certificate
from acme_helper.state import DeployState
from tests.conftest import make_cert
from tests.test_deploy import FakeFortiWeb


def test_group_follows_chain_and_old_intermediates_are_removed(cfg, lineage):
    fw = FakeFortiWeb()
    state = DeployState(cfg.state_dir)
    cert, target = cfg.certificates[0], cfg.certificates[0].deploy[0]

    # Staging-Deploy: Inter_Cert_1 in der Gruppe
    deploy_certificate(cfg, cert, target, state=state, client=fw)
    assert [m["name"] for m in fw.groups["wc-example-chain"]] == ["Inter_Cert_1"]
    assert fw.inter == ["Inter_Cert_1"]

    # Neues Zertifikat mit anderer Kette (Produktion)
    leaf, key = make_cert("*.example.com", "Prod Intermediate")
    inter, _ = make_cert("Prod Intermediate", "Prod Root")
    (lineage / "cert.pem").write_text(leaf)
    (lineage / "privkey.pem").write_text(key)
    (lineage / "chain.pem").write_text(inter)
    (lineage / "fullchain.pem").write_text(leaf + inter)

    res = deploy_certificate(cfg, cert, target, state=state, client=fw)
    assert res.changed
    assert [m["name"] for m in fw.groups["wc-example-chain"]] == ["Inter_Cert_2"]
    assert fw.inter == ["Inter_Cert_2"]  # Staging-Intermediate gelöscht
    assert list(state.intermediates("fw1").values()) == ["Inter_Cert_2"]
    assert any("aus Gruppe" in m for m in res.messages) and any("gelöscht (nicht mehr benötigt)" in m for m in res.messages)


def test_foreign_group_members_are_not_touched_if_not_ours(cfg, lineage):
    """Ein Member, der nicht zur Kette gehört, wird aus der (acme-helper-eigenen) Gruppe entfernt,
    das zugehörige Zertifikat aber nur gelöscht, wenn acme-helper es selbst hochgeladen hat."""
    fw = FakeFortiWeb()
    fw.inter = ["Manual_CA"]
    fw.groups["wc-example-chain"] = [{"id": "1", "name": "Manual_CA"}]
    state = DeployState(cfg.state_dir)
    cert, target = cfg.certificates[0], cfg.certificates[0].deploy[0]
    deploy_certificate(cfg, cert, target, state=state, client=fw)
    assert [m["name"] for m in fw.groups["wc-example-chain"]] == ["Inter_Cert_2"]
    assert "Manual_CA" in fw.inter  # nicht von uns, bleibt bestehen

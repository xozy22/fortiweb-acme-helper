from datetime import datetime, timezone

import pytest

from acme_helper.errors import FortiWebError
from acme_helper.fortiweb.deploy import deploy_certificate, old_certificates, unique_name
from acme_helper.state import DeployState


class FakeFortiWeb:
    """In-Memory-Nachbildung der genutzten Client-Methoden."""

    def __init__(self):
        self.local = ["wc-example-20260101", "wc-example-20260401", "unrelated"]
        self.inter: list[str] = []
        self.groups: dict[str, list[dict]] = {}
        self.policies = {"pol1": {"name": "pol1", "certificate": "wc-example-20260401", "certificate-type": "enable"}}
        self.sni = {"sni1": [{"id": 1, "domain": "*.example.com", "local-cert": "x"}, {"id": 2, "domain": "other.org", "local-cert": "y"}]}
        self.deleted: list[str] = []

    def list_local_certificates(self):
        return list(self.local)

    def import_local_certificate(self, name, cert, key):
        self.local.append(name)
        return name

    def delete_local_certificate(self, name):
        if name == "wc-example-20260401":
            raise FortiWebError("still referenced")
        self.local.remove(name)
        self.deleted.append(name)

    def list_intermediate_certificates(self):
        return list(self.inter)

    def import_intermediate_certificate(self, name, pem):
        # FortiWeb 8.0.7 ignoriert den Dateinamen und nummeriert selbst
        assigned = f"Inter_Cert_{len(self.inter) + 1}"
        self.inter.append(assigned)
        return assigned

    def get_intermediate_group(self, name):
        return {"name": name} if name in self.groups else None

    def create_intermediate_group(self, name):
        self.groups[name] = []

    def list_intermediate_group_members(self, group):
        return self.groups[group]

    def add_intermediate_group_member(self, group, cert):
        self.groups[group].append({"id": str(len(self.groups[group]) + 1), "name": cert})

    def delete_intermediate_group_member(self, group, member_id):
        self.groups[group] = [m for m in self.groups[group] if str(m["id"]) != str(member_id)]

    def delete_intermediate_certificate(self, name):
        for g in self.groups.values():
            if any(m["name"] == name for m in g):
                raise FortiWebError("still referenced")
        self.inter.remove(name)

    def get_server_policy(self, name):
        return dict(self.policies[name]) if name in self.policies else None

    def update_server_policy(self, name, changes):
        self.policies[name].update(changes)

    def get_sni_group(self, name):
        return {"name": name} if name in self.sni else None

    def create_sni_group(self, name):
        self.sni[name] = []

    def list_sni_members(self, group):
        return [dict(m) for m in self.sni[group]]

    def add_sni_member(self, group, data):
        m = {"id": str(len(self.sni[group]) + 1), **data}
        self.sni[group].append(m)
        return m

    def update_sni_member(self, group, member, changes):
        for m in self.sni[group]:
            if str(m["id"]) == str(member["id"]):
                m.update(changes)


def test_unique_name_and_old_certificates():
    today = datetime(2026, 9, 7, tzinfo=timezone.utc)
    assert unique_name("wc", set(), today) == "wc-20260907"
    assert unique_name("wc", {"wc-20260907"}, today) == "wc-20260907-2"
    names = ["wc-20260101", "wc-20260907", "wc-20260907-2", "wcx-20260101", "wc-foo", "other"]
    assert old_certificates("wc", names, "wc-20260907-2") == ["wc-20260907", "wc-20260101"]


def test_full_deploy_flow(cfg, lineage):
    fw = FakeFortiWeb()
    state = DeployState(cfg.state_dir)
    cert = cfg.certificates[0]
    target = cert.deploy[0]

    res = deploy_certificate(cfg, cert, target, state=state, client=fw)
    assert res.changed
    new = res.fw_cert_name
    assert new.startswith("wc-example-") and new in fw.local
    # Policy zeigt auf neues Zertifikat, ACME-Typ abgeschaltet, Intermediate-Gruppe gesetzt
    assert fw.policies["pol1"]["certificate"] == new
    assert fw.policies["pol1"]["certificate-type"] == "disable"
    assert fw.policies["pol1"]["intermediate-certificate-group"] == "wc-example-chain"
    assert len(fw.groups["wc-example-chain"]) == 1 and fw.inter == ["Inter_Cert_1"]
    assert fw.groups["wc-example-chain"][0]["name"] == "Inter_Cert_1"
    # Nur der passende SNI-Member wurde umgestellt, other.org bleibt; Policy hat SNI mit der Gruppe aktiv
    assert fw.sni["sni1"][0]["local-cert"] == new
    assert fw.sni["sni1"][1]["local-cert"] == "y"
    assert fw.policies["pol1"]["sni"] == "enable" and fw.policies["pol1"]["sni-certificate"] == "sni1"
    # keep_old=1: 20260401 bleibt, 20260101 wird gelöscht
    assert fw.deleted == ["wc-example-20260101"]
    assert state.get("wc-example", "fw1")["fw_cert_name"] == new

    # Zweiter Lauf: unverändert, kein Upload
    before = list(fw.local)
    res2 = deploy_certificate(cfg, cert, target, state=state, client=fw)
    assert not res2.changed and fw.local == before

    # force: neuer Name mit Suffix am selben Tag; der Vorgänger ist jetzt "alt" und wird behalten (keep_old=1),
    # 20260401 fällt raus, lässt sich aber nicht löschen -> Warnung statt Abbruch
    res3 = deploy_certificate(cfg, cert, target, state=state, client=fw, force=True)
    assert res3.changed and res3.fw_cert_name == new + "-2"
    assert new in fw.local
    assert any("konnte nicht gelöscht" in w for w in res3.warnings)
    # Das Intermediate wurde nicht erneut hochgeladen (Fingerprint -> Name im State)
    assert fw.inter == ["Inter_Cert_1"]
    assert state.intermediate_name("fw1", __import__("acme_helper.fortiweb.deploy", fromlist=["cert_fingerprint"]).cert_fingerprint(
        (lineage / "chain.pem").read_text())) == "Inter_Cert_1"


def test_verification_failure(cfg, lineage):
    fw = FakeFortiWeb()
    fw.update_server_policy = lambda name, changes: None  # Änderung geht "verloren"
    with pytest.raises(FortiWebError, match="Verifikation"):
        deploy_certificate(cfg, cfg.certificates[0], cfg.certificates[0].deploy[0], state=DeployState(cfg.state_dir), client=fw)


def test_missing_lineage(cfg):
    with pytest.raises(FortiWebError, match="Lineage"):
        deploy_certificate(cfg, cfg.certificates[0], cfg.certificates[0].deploy[0], state=DeployState(cfg.state_dir), client=FakeFortiWeb())

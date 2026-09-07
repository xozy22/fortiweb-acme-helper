"""Deploy-Ablauf: Lineage lesen -> Upload -> Chain -> Bindings -> Verify -> Cleanup -> State."""

from __future__ import annotations

import fnmatch
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from ..config import Config, CertificateConfig, DeployTarget
from ..errors import FortiWebError
from ..state import DeployState
from .client import FortiWebClient, get_field

log = logging.getLogger(__name__)

PEM_RE = re.compile(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.S)


@dataclass
class Lineage:
    name: str
    cert_pem: str
    key_pem: str
    chain_pem: str
    fullchain_pem: str
    fingerprint: str
    not_after: datetime
    subject: str

    @classmethod
    def load(cls, live_dir: Path, name: str) -> "Lineage":
        base = live_dir / name
        if not (base / "cert.pem").is_file():
            raise FortiWebError(f"Lineage '{name}' fehlt unter {base} (certbot noch nicht gelaufen?)")
        cert_pem = (base / "cert.pem").read_text(encoding="utf-8")
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        return cls(
            name=name,
            cert_pem=cert_pem,
            key_pem=(base / "privkey.pem").read_text(encoding="utf-8"),
            chain_pem=(base / "chain.pem").read_text(encoding="utf-8") if (base / "chain.pem").is_file() else "",
            fullchain_pem=(base / "fullchain.pem").read_text(encoding="utf-8"),
            fingerprint=cert.fingerprint(hashes.SHA256()).hex(),
            not_after=cert.not_valid_after_utc,
            subject=cert.subject.rfc4514_string(),
        )


@dataclass
class DeployResult:
    fortiweb: str
    changed: bool
    fw_cert_name: str | None = None
    messages: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def split_pem_certs(pem: str) -> list[str]:
    return PEM_RE.findall(pem)


def cert_fingerprint(pem: str) -> str:
    return x509.load_pem_x509_certificate(pem.encode()).fingerprint(hashes.SHA256()).hex()


def unique_name(prefix: str, existing: set[str], today: datetime | None = None) -> str:
    stamp = (today or datetime.now(timezone.utc)).strftime("%Y%m%d")
    base = f"{prefix}-{stamp}"
    if base not in existing:
        return base
    n = 2
    while f"{base}-{n}" in existing:
        n += 1
    return f"{base}-{n}"


def old_certificates(prefix: str, names: list[str], current: str) -> list[str]:
    """Alle Zertifikate mit unserem Prefix außer dem aktuellen, neueste zuerst."""
    pat = re.compile(rf"^{re.escape(prefix)}-\d{{8}}(-\d+)?$")
    return sorted((n for n in names if pat.match(n) and n != current), reverse=True)


def sni_member_matches(member: dict, patterns: list[str]) -> bool:
    if not patterns:
        return True
    domain = str(get_field(member, "domain", "")).lower()
    return any(fnmatch.fnmatchcase(domain, p.lower()) or domain == p.lower() for p in patterns)


def ensure_intermediate_group(client: FortiWebClient, group: str, chain_pem: str, result: DeployResult) -> str | None:
    certs = split_pem_certs(chain_pem)
    if not certs:
        result.warnings.append("chain.pem enthält keine Intermediates, Gruppe nicht angepasst")
        return None
    existing_names = client.list_intermediate_certificates()
    wanted: list[str] = []
    for pem in certs:
        fp = cert_fingerprint(pem)
        name = f"le-{fp[:16]}"
        if name not in existing_names:
            name = client.import_intermediate_certificate(name, pem + "\n")
            result.messages.append(f"Intermediate '{name}' hochgeladen")
        wanted.append(name)
    if client.get_intermediate_group(group) is None:
        client.create_intermediate_group(group)
        result.messages.append(f"Intermediate-Gruppe '{group}' angelegt")
    members = client.list_intermediate_group_members(group)
    present = {str(get_field(m, "name", "")) for m in members}
    for name in wanted:
        if name not in present:
            client.add_intermediate_group_member(group, name)
            result.messages.append(f"'{name}' in Gruppe '{group}' aufgenommen")
    return group


def bind_server_policy(client: FortiWebClient, policy: str, fw_cert: str, inter_group: str | None, result: DeployResult) -> None:
    current = client.get_server_policy(policy)
    if current is None:
        raise FortiWebError(f"Server Policy '{policy}' existiert nicht auf FortiWeb")
    changes: dict = {"certificate": fw_cert}
    if inter_group:
        changes["intermediate-certificate-group"] = inter_group
    if str(get_field(current, "certificate-type", "")).lower() == "enable":
        changes["certificate-type"] = "disable"  # war FortiWeb-eigenes ACME
        result.messages.append(f"Policy '{policy}': certificate-type von Let's Encrypt auf lokales Zertifikat umgestellt")
    if str(get_field(current, "multi-certificate", "")).lower() == "enable":
        result.warnings.append(
            f"Policy '{policy}': multi-certificate ist aktiv, das Feld 'certificate' wird dort evtl. ignoriert"
        )
    client.update_server_policy(policy, changes)
    after = client.get_server_policy(policy) or {}
    if str(get_field(after, "certificate", "")) != fw_cert:
        raise FortiWebError(f"Verifikation fehlgeschlagen: Policy '{policy}' referenziert nicht '{fw_cert}'")
    result.messages.append(f"Policy '{policy}' -> '{fw_cert}'")


def bind_sni(client: FortiWebClient, group: str, patterns: list[str], fw_cert: str, inter_group: str | None, result: DeployResult) -> None:
    if client.get_sni_group(group) is None:
        raise FortiWebError(f"SNI-Gruppe '{group}' existiert nicht auf FortiWeb")
    members = client.list_sni_members(group)
    hits = [m for m in members if sni_member_matches(m, patterns)]
    if not hits:
        result.warnings.append(f"SNI-Gruppe '{group}': kein Member passt zu {patterns or 'allen'}")
        return
    for m in hits:
        changes: dict = {"local-cert": fw_cert}
        if inter_group:
            changes["inter-group"] = inter_group
        if str(get_field(m, "certificate-type", "")).lower() == "enable":
            changes["certificate-type"] = "disable"
        client.update_sni_member(group, m, changes)
    after = {str(get_field(m, "id") or get_field(m, "name")): m for m in client.list_sni_members(group)}
    for m in hits:
        mid = str(get_field(m, "id") or get_field(m, "name"))
        if str(get_field(after.get(mid, {}), "local-cert", "")) != fw_cert:
            raise FortiWebError(f"Verifikation fehlgeschlagen: SNI {group}/{mid} referenziert nicht '{fw_cert}'")
    result.messages.append(f"SNI '{group}': {len(hits)} Member -> '{fw_cert}'")


def deploy_certificate(
    cfg: Config,
    cert_cfg: CertificateConfig,
    target: DeployTarget,
    *,
    state: DeployState,
    force: bool = False,
    client: FortiWebClient | None = None,
) -> DeployResult:
    result = DeployResult(fortiweb=target.fortiweb, changed=False)
    lineage = Lineage.load(cfg.letsencrypt_dir / "live", cert_cfg.name)
    prev = state.get(cert_cfg.name, target.fortiweb)
    same_cert = bool(prev and prev.get("fingerprint") == lineage.fingerprint)
    if same_cert and prev.get("phase", "bound") == "bound" and not force:
        result.fw_cert_name = prev.get("fw_cert_name")
        result.messages.append(f"unverändert (Fingerprint {lineage.fingerprint[:16]}…, als '{prev.get('fw_cert_name')}')")
        return result

    client = client or FortiWebClient.from_config(target.fortiweb, cfg.fortiwebs[target.fortiweb])
    existing = set(client.list_local_certificates())
    fw_name: str | None = None
    # Ein früherer Versuch hat das Leaf schon hochgeladen, ist aber beim Binden gescheitert:
    # dieselbe Datei wiederverwenden statt eine weitere Kopie anzulegen.
    if same_cert and not force and prev.get("fw_cert_name") in existing:
        fw_name = prev["fw_cert_name"]
        result.messages.append(f"'{fw_name}' bereits hochgeladen, setze beim Binden fort")
    if fw_name is None:
        new_name = unique_name(target.cert_name_prefix, existing)
        body = lineage.fullchain_pem if target.chain_mode == "fullchain" else lineage.cert_pem
        fw_name = client.import_local_certificate(new_name, body, lineage.key_pem)
        result.messages.append(f"'{fw_name}' hochgeladen (gültig bis {lineage.not_after:%Y-%m-%d})")
        state.set(
            cert_cfg.name,
            target.fortiweb,
            fingerprint=lineage.fingerprint,
            fw_cert_name=fw_name,
            extra={"phase": "uploaded", "not_after": lineage.not_after.isoformat()},
        )
    result.fw_cert_name = fw_name

    inter_group: str | None = None
    if target.chain_mode == "intermediate-group":
        inter_group = ensure_intermediate_group(
            client, target.intermediate_group or f"{target.cert_name_prefix}-chain", lineage.chain_pem, result
        )

    for policy in target.server_policies:
        bind_server_policy(client, policy, fw_name, inter_group, result)
    for sni in target.sni:
        bind_sni(client, sni.group, sni.domains, fw_name, inter_group, result)

    # Alte Versionen aufräumen (neueste keep_old behalten)
    for old in old_certificates(target.cert_name_prefix, client.list_local_certificates(), fw_name)[target.keep_old :]:
        try:
            client.delete_local_certificate(old)
            result.messages.append(f"alt: '{old}' gelöscht")
        except FortiWebError as exc:
            result.warnings.append(f"'{old}' konnte nicht gelöscht werden (noch referenziert?): {exc}")

    state.set(
        cert_cfg.name,
        target.fortiweb,
        fingerprint=lineage.fingerprint,
        fw_cert_name=fw_name,
        extra={"phase": "bound", "not_after": lineage.not_after.isoformat(), "intermediate_group": inter_group},
    )
    result.changed = True
    return result

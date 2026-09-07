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

from ..config import Config, CertificateConfig, DeployTarget, SniBinding
from ..errors import FortiWebError
from ..state import DeployState
from .client import FortiWebClient, get_field, member_id

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


def ensure_intermediate_group(
    client: FortiWebClient,
    group: str,
    chain_pem: str,
    result: DeployResult,
    *,
    state: DeployState | None = None,
    fortiweb: str = "",
) -> str | None:
    certs = split_pem_certs(chain_pem)
    if not certs:
        result.warnings.append("chain.pem enthält keine Intermediates, Gruppe nicht angepasst")
        return None
    existing_names = client.list_intermediate_certificates()
    wanted: list[str] = []
    for pem in certs:
        fp = cert_fingerprint(pem)
        # Die FortiWeb vergibt Intermediate-Namen selbst; der State merkt sich Fingerprint -> Name
        name = state.intermediate_name(fortiweb, fp) if state else None
        if name is None or name not in existing_names:
            name = client.import_intermediate_certificate(f"le-{fp[:16]}", pem + "\n")
            if state:
                state.set_intermediate_name(fortiweb, fp, name)
            result.messages.append(f"Intermediate hochgeladen als '{name}'")
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
    # Die Gruppe gehört acme-helper: Member, die nicht zur aktuellen Kette gehören, fliegen raus
    # (z.B. Staging-Intermediates nach dem Wechsel auf Produktion).
    for m in members:
        name = str(get_field(m, "name", ""))
        if name and name not in wanted:
            try:
                client.delete_intermediate_group_member(group, member_id(m))
                result.messages.append(f"'{name}' aus Gruppe '{group}' entfernt")
            except FortiWebError as exc:
                result.warnings.append(f"Member '{name}' konnte nicht aus '{group}' entfernt werden: {exc}")
    # Selbst hochgeladene Intermediates, die keine Kette mehr braucht, wieder löschen
    if state:
        for fp, name in list(state.intermediates(fortiweb).items()):
            if name in wanted:
                continue
            if name in existing_names:
                try:
                    client.delete_intermediate_certificate(name)
                    result.messages.append(f"Intermediate '{name}' gelöscht (nicht mehr benötigt)")
                except FortiWebError as exc:
                    result.warnings.append(f"Intermediate '{name}' konnte nicht gelöscht werden (noch referenziert?): {exc}")
                    continue
            state.forget_intermediate(fortiweb, fp)
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


def wildcard_regex(domain: str) -> str:
    """'*.example.com' -> Regex für genau eine Label-Ebene darunter."""
    return rf"^[^.]+\.{re.escape(domain[2:])}$"


def sni_member_spec(pattern: str, wildcard_mode: str) -> tuple[str, str]:
    """Liefert (domain, domain-type) für einen anzulegenden SNI-Member."""
    if pattern.startswith("*.") and wildcard_mode == "regex":
        return wildcard_regex(pattern), "regular"
    return pattern, "plain"


def _member_matches_pattern(member: dict, pattern: str, wanted_domain: str) -> bool:
    domain = str(get_field(member, "domain", "")).lower()
    if domain == wanted_domain.lower():
        return True
    if str(get_field(member, "domain-type", "plain")).lower() != "plain":
        return False
    return fnmatch.fnmatchcase(domain, pattern.lower())


def bind_sni(
    client: FortiWebClient,
    binding: SniBinding,
    cert_domains: list[str],
    policies: list[str],
    fw_cert: str,
    inter_group: str | None,
    result: DeployResult,
) -> None:
    group = binding.group
    if client.get_sni_group(group) is None:
        if not binding.create:
            raise FortiWebError(f"SNI-Gruppe '{group}' existiert nicht auf FortiWeb (create: false)")
        client.create_sni_group(group)
        result.messages.append(f"SNI-Gruppe '{group}' angelegt")

    base_changes: dict = {"local-cert": fw_cert}
    if inter_group:
        base_changes["inter-group"] = inter_group
    patterns = binding.domains or cert_domains
    members = client.list_sni_members(group)
    updated_ids: set[str] = set()
    created_domains: list[str] = []
    for pattern in patterns:
        wanted_domain, wanted_type = sni_member_spec(pattern, binding.wildcard)
        hits = [m for m in members if _member_matches_pattern(m, pattern, wanted_domain)]
        if not hits:
            if not binding.create:
                result.warnings.append(f"SNI-Gruppe '{group}': kein Member für '{pattern}' (create: false)")
                continue
            client.add_sni_member(group, {"domain": wanted_domain, "domain-type": wanted_type, **base_changes})
            created_domains.append(wanted_domain)
            result.messages.append(f"SNI '{group}': Member '{wanted_domain}' ({wanted_type}) angelegt")
            continue
        for m in hits:
            mid = member_id(m)
            if mid in updated_ids:
                continue
            changes = dict(base_changes)
            if str(get_field(m, "certificate-type", "")).lower() == "enable":
                changes["certificate-type"] = "disable"
            client.update_sni_member(group, m, changes)
            updated_ids.add(mid)

    # Verifikation
    after = client.list_sni_members(group)
    by_id = {member_id(m): m for m in after}
    for mid in updated_ids:
        if str(get_field(by_id.get(mid, {}), "local-cert", "")) != fw_cert:
            raise FortiWebError(f"Verifikation fehlgeschlagen: SNI {group}/{mid} referenziert nicht '{fw_cert}'")
    for domain in created_domains:
        ok = any(
            str(get_field(m, "domain", "")).lower() == domain.lower() and str(get_field(m, "local-cert", "")) == fw_cert
            for m in after
        )
        if not ok:
            raise FortiWebError(f"Verifikation fehlgeschlagen: SNI-Member '{domain}' in '{group}' fehlt oder falsch")
    if updated_ids or created_domains:
        result.messages.append(
            f"SNI '{group}': {len(updated_ids)} Member aktualisiert, {len(created_domains)} angelegt -> '{fw_cert}'"
        )

    # SNI in den Policies aktivieren und die Gruppe eintragen
    for policy in policies:
        current = client.get_server_policy(policy)
        if current is None:
            raise FortiWebError(f"Server Policy '{policy}' existiert nicht auf FortiWeb")
        changes = {}
        if str(get_field(current, "sni", "")).lower() != "enable":
            changes["sni"] = "enable"
        if str(get_field(current, "sni-certificate", "")) != group:
            changes["sni-certificate"] = group
        if binding.strict is not None:
            wanted = "enable" if binding.strict else "disable"
            if str(get_field(current, "sni-strict", "")).lower() != wanted:
                changes["sni-strict"] = wanted
        if not changes:
            continue
        client.update_server_policy(policy, changes)
        check = client.get_server_policy(policy) or {}
        if str(get_field(check, "sni", "")).lower() != "enable" or str(get_field(check, "sni-certificate", "")) != group:
            raise FortiWebError(f"Verifikation fehlgeschlagen: Policy '{policy}' hat SNI-Gruppe '{group}' nicht übernommen")
        result.messages.append(f"Policy '{policy}': SNI aktiv mit Gruppe '{group}'")


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
            client,
            target.intermediate_group or f"{target.cert_name_prefix}-chain",
            lineage.chain_pem,
            result,
            state=state,
            fortiweb=target.fortiweb,
        )

    if target.bind_default_certificate:
        for policy in target.server_policies:
            bind_server_policy(client, policy, fw_name, inter_group, result)
    for sni in target.sni:
        policies = target.server_policies if sni.policies is None else sni.policies
        bind_sni(client, sni, cert_cfg.domains, policies, fw_name, inter_group, result)

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

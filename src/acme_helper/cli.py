"""Kommandozeile: run | check | deploy | dns-test | list"""

from __future__ import annotations

import argparse
import json
import logging
import os
import secrets
import sys

from . import __version__, certbot_runner
from .config import Config, StratoProvider, env_secret, load_config
from .dns import build_provider, match_zone, provider_for
from .dns.resolver import challenge_name, follow_cname, txt_visible
from .errors import AcmeHelperError
from .fortiweb.client import FortiWebClient
from .jobs import deploy_all, run_once
from .logsetup import setup_logging
from .scheduler import run_forever
from .state import DeployState

log = logging.getLogger("acme_helper")


# --- Kommandos -------------------------------------------------------------
def cmd_run(cfg: Config, args: argparse.Namespace) -> int:
    def job() -> None:
        errors = run_once(cfg, force_renew=args.force_renew, dry_run=args.dry_run, only=args.cert)
        log.info("Lauf abgeschlossen, Fehler: %d", errors)

    if args.once or args.dry_run:
        return 1 if run_once(cfg, force_renew=args.force_renew, dry_run=args.dry_run, only=args.cert) else 0
    run_forever(job, cfg.schedule)
    return 0


def cmd_deploy(cfg: Config, args: argparse.Namespace) -> int:
    cfg.certificate(args.cert)  # validiert den Namen
    return 1 if deploy_all(cfg, only=args.cert, force=args.force) else 0


def cmd_show_config(cfg: Config, args: argparse.Namespace) -> int:
    """Effektive Konfiguration als YAML. Enthält nur Env-Variablennamen, keine Secret-Werte."""
    import yaml

    print(f"# Quelle: {cfg.source}")
    print(yaml.safe_dump(cfg.model_dump(mode="json", exclude_none=True), sort_keys=False, allow_unicode=True))
    return 0


def cmd_list(cfg: Config, args: argparse.Namespace) -> int:
    state = DeployState(cfg.state_dir).all()
    lineages = certbot_runner.list_lineages(cfg)
    print(f"Lineages unter {cfg.letsencrypt_dir / 'live'}: {', '.join(lineages) or '-'}")
    for cert in cfg.certificates:
        print(f"\n{cert.name}: {', '.join(cert.domains)}")
        fp = certbot_runner.lineage_fingerprint(cfg, cert.name)
        print(f"  lokal: {'Fingerprint ' + fp[:16] + '…' if fp else 'noch nicht ausgestellt'}")
        for t in cert.deploy:
            st = state.get(cert.name, {}).get(t.fortiweb)
            if st:
                status = f"'{st['fw_cert_name']}' seit {st['deployed_at']} ({'aktuell' if st['fingerprint'] == fp else 'VERALTET'})"
            else:
                status = "noch nicht deployt"
            print(f"  {t.fortiweb}: {status}")
    return 0


def cmd_dns_test(cfg: Config, args: argparse.Namespace) -> int:
    fqdn = args.fqdn.rstrip(".").lower()
    if not fqdn.startswith("_acme-challenge."):
        fqdn = challenge_name(fqdn)
    target = follow_cname(fqdn)
    zone, provider = provider_for(cfg, target)
    value = args.value or f"acme-helper-test-{secrets.token_hex(8)}"
    print(f"{fqdn} -> {target} | Zone {zone.suffix} | Provider {zone.provider} ({provider.__class__.__name__})")
    print(f"Setze TXT '{value}' ...")
    provider.add_txt(target, value)
    try:
        import time

        deadline = time.monotonic() + args.timeout
        while True:
            if txt_visible(target, value):
                print("TXT auf autoritativem Nameserver sichtbar.")
                break
            if time.monotonic() > deadline:
                print("WARNUNG: TXT innerhalb des Timeouts nicht sichtbar.")
                break
            time.sleep(5)
    finally:
        if not args.keep:
            provider.remove_txt(target, value)
            print("TXT wieder entfernt.")
    return 0


def cmd_check(cfg: Config, args: argparse.Namespace) -> int:
    problems = 0

    def ok(msg: str) -> None:
        print(f"  [ok]   {msg}")

    def fail(msg: str) -> None:
        nonlocal problems
        problems += 1
        print(f"  [FAIL] {msg}")

    print(f"Konfiguration: {cfg.source}")
    print(f"ACME: {cfg.acme.email}, {'STAGING' if cfg.acme.staging else 'Produktion'}, Key {cfg.acme.key_type}")

    print("\nDNS-Provider:")
    used = {z.provider for z in cfg.zones}
    for name in cfg.dns_providers:
        if name not in used:
            print(f"  [warn] '{name}' wird von keiner Zone verwendet")
            continue
        try:
            provider = build_provider(cfg, name)
        except AcmeHelperError as exc:
            fail(f"{name}: {exc}")
            continue
        pcfg = cfg.dns_providers[name]
        if pcfg.type == "cloudflare":
            for z in (z for z in cfg.zones if z.provider == name):
                try:
                    provider.zone_id(z.suffix)  # type: ignore[attr-defined]
                    ok(f"{name}: Zone {z.suffix} erreichbar")
                except AcmeHelperError as exc:
                    fail(f"{name}: {exc}")
        elif isinstance(pcfg, StratoProvider):
            if args.probe:
                try:
                    c = provider.client()  # type: ignore[attr-defined]
                    pk = c.list_packages()
                    ok(f"{name}: Login ok, {len(pk)} Paket(e): {'; '.join(t[:60] for _, t in pk)}")
                except AcmeHelperError as exc:
                    fail(f"{name}: {exc}")
            else:
                ok(f"{name}: Zugangsdaten vorhanden (Login-Test mit --probe)")
        else:
            ok(f"{name}: Token vorhanden (do.de bietet keinen Lese-Endpunkt)")

    print("\nDomains -> Challenge-Ziel:")
    for cert in cfg.certificates:
        for d in cert.domains:
            fqdn = challenge_name(d)
            try:
                target = follow_cname(fqdn)
                zone = match_zone(target, cfg.zones)
                if zone is None:
                    fail(f"{d}: {fqdn} -> {target}: keine passende Zone in 'zones'")
                else:
                    ok(f"{d}: {fqdn}{' -> ' + target if target != fqdn else ''} => {zone.provider}")
            except AcmeHelperError as exc:
                fail(f"{d}: {exc}")

    print("\nFortiWeb:")
    for name, fwcfg in cfg.fortiwebs.items():
        try:
            client = FortiWebClient.from_config(name, fwcfg)
            certs = client.list_local_certificates()
            ok(f"{name}: verbunden, {len(certs)} lokale Zertifikate")
        except AcmeHelperError as exc:
            fail(f"{name}: {exc}")
            continue
        if args.probe:
            for key, status in client.probe_endpoints().items():
                (ok if status == "ok" else fail)(f"{name}: Endpunkt {key}: {status}")
        for cert in cfg.certificates:
            for t in cert.deploy:
                if t.fortiweb != name:
                    continue
                for p in t.server_policies:
                    try:
                        pol = client.get_server_policy(p)
                        if pol is None:
                            fail(f"{name}: Server Policy '{p}' nicht gefunden")
                        else:
                            from .fortiweb.client import get_field

                            ok(f"{name}: Policy '{p}' (certificate={get_field(pol, 'certificate')!r})")
                    except AcmeHelperError as exc:
                        fail(f"{name}: Policy '{p}': {exc}")
                for s in t.sni:
                    try:
                        if client.get_sni_group(s.group) is None:
                            fail(f"{name}: SNI-Gruppe '{s.group}' nicht gefunden")
                        else:
                            members = client.list_sni_members(s.group)
                            ok(f"{name}: SNI-Gruppe '{s.group}' mit {len(members)} Member(n)")
                    except AcmeHelperError as exc:
                        fail(f"{name}: SNI '{s.group}': {exc}")

    print(f"\nErgebnis: {'alles in Ordnung' if problems == 0 else f'{problems} Problem(e)'}")
    return 1 if problems else 0


# --- Parser ----------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="acme-helper", description="ACME DNS-01 für FortiWeb")
    p.add_argument("--config", help="Pfad zur config.yaml (Default: $ACME_HELPER_CONFIG oder /config/config.yaml)")
    p.add_argument("--log-level", default=None)
    p.add_argument("--version", action="version", version=f"acme-helper {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    r = sub.add_parser("run", help="Zertifikate holen/erneuern und deployen (Daemon, außer --once)")
    r.add_argument("--once", action="store_true", help="einmal ausführen und beenden")
    r.add_argument("--force-renew", action="store_true", help="Erneuerung erzwingen")
    r.add_argument("--dry-run", action="store_true", help="certbot --dry-run gegen Staging, kein Deploy")
    r.add_argument("--cert", help="nur dieses Zertifikat")
    r.set_defaults(func=cmd_run)

    c = sub.add_parser("check", help="Konfiguration, Provider und FortiWeb-Verbindung prüfen")
    c.add_argument("--probe", action="store_true", help="zusätzlich Strato-Login und alle FortiWeb-Endpunkte testen")
    c.set_defaults(func=cmd_check)

    d = sub.add_parser("deploy", help="vorhandenes Zertifikat (erneut) auf FortiWeb bringen")
    d.add_argument("cert")
    d.add_argument("--force", action="store_true", help="auch wenn Fingerprint unverändert")
    d.set_defaults(func=cmd_deploy)

    t = sub.add_parser("dns-test", help="Test-TXT setzen, prüfen, entfernen")
    t.add_argument("fqdn", help="Domain oder _acme-challenge.<domain>")
    t.add_argument("--value")
    t.add_argument("--timeout", type=int, default=120)
    t.add_argument("--keep", action="store_true", help="TXT nicht wieder löschen")
    t.set_defaults(func=cmd_dns_test)

    ls = sub.add_parser("list", help="Status der Zertifikate und Deployments")
    ls.set_defaults(func=cmd_list)

    sc = sub.add_parser("show-config", help="effektive Konfiguration anzeigen (aus Datei oder Env-Variablen)")
    sc.set_defaults(func=cmd_show_config)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    setup_logging(args.log_level)
    if args.config:
        os.environ["ACME_HELPER_CONFIG"] = args.config
    try:
        cfg = load_config(args.config)
        return int(args.func(cfg, args))
    except AcmeHelperError as exc:
        log.error("%s", exc)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())

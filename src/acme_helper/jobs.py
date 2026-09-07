"""Die eigentlichen Arbeitsschritte, von CLI und Scheduler genutzt."""

from __future__ import annotations

import logging

from . import certbot_runner
from .config import Config
from .errors import AcmeHelperError
from .fortiweb.deploy import deploy_certificate
from .notify import notify
from .state import DeployState

log = logging.getLogger(__name__)


def run_once(cfg: Config, *, force_renew: bool = False, dry_run: bool = False, only: str | None = None) -> int:
    """Alle Zertifikate holen/erneuern und auf die FortiWebs bringen. Liefert Fehleranzahl."""
    errors = 0
    certs = [c for c in cfg.certificates if only is None or c.name == only]
    if only and not certs:
        raise AcmeHelperError(f"Zertifikat '{only}' ist nicht konfiguriert")

    renewed: set[str] = set()
    for cert in certs:
        try:
            if certbot_runner.obtain_or_renew(cfg, cert, force=force_renew, dry_run=dry_run):
                renewed.add(cert.name)
        except AcmeHelperError as exc:
            errors += 1
            log.error("%s", exc)
            notify(cfg.notify, status="failure", message=f"ACME für '{cert.name}' fehlgeschlagen", details={"error": str(exc)})

    if dry_run:
        log.info("Dry-Run: Deploy übersprungen")
        return errors

    errors += deploy_all(cfg, only=only)
    return errors


def deploy_all(cfg: Config, *, only: str | None = None, force: bool = False) -> int:
    errors = 0
    state = DeployState(cfg.state_dir)
    for cert in cfg.certificates:
        if only and cert.name != only:
            continue
        for target in cert.deploy:
            try:
                res = deploy_certificate(cfg, cert, target, state=state, force=force)
            except AcmeHelperError as exc:
                errors += 1
                log.error("Deploy '%s' -> %s fehlgeschlagen: %s", cert.name, target.fortiweb, exc)
                notify(
                    cfg.notify,
                    status="failure",
                    message=f"Deploy '{cert.name}' auf {target.fortiweb} fehlgeschlagen",
                    details={"error": str(exc)},
                )
                continue
            for m in res.messages:
                log.info("Deploy '%s' -> %s: %s", cert.name, target.fortiweb, m)
            for w in res.warnings:
                log.warning("Deploy '%s' -> %s: %s", cert.name, target.fortiweb, w)
            if res.changed:
                notify(
                    cfg.notify,
                    status="success",
                    message=f"'{cert.name}' auf {target.fortiweb} als '{res.fw_cert_name}' aktiv",
                    details={"messages": res.messages, "warnings": res.warnings},
                )
    return errors

"""certbot-Aufrufe: certonly mit manual-Hooks, --keep-until-expiring entscheidet über Renewal."""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from .config import DEFAULT_CONFIG_PATH, CertificateConfig, Config, env_secret
from .errors import CertbotError
from .state import PendingTxtState

log = logging.getLogger(__name__)


def certbot_executable() -> str:
    exe = shutil.which("certbot")
    if exe:
        return exe
    raise CertbotError("certbot nicht gefunden (pip install certbot)")


def hook_command(module: str) -> str:
    """certbot validiert das erste Wort des Hook-Befehls per PATH-Suche, daher ohne Anführungszeichen.

    Bevorzugt die installierten Konsolenskripte (acme-helper-auth-hook / -cleanup-hook),
    sonst der Python-Interpreter mit -m.
    """
    script = shutil.which(f"acme-helper-{module}-hook")
    if script:
        return script
    return f"{sys.executable} -m acme_helper.hooks.{module}"


def lineage_fingerprint(cfg: Config, name: str) -> str | None:
    cert = cfg.letsencrypt_dir / "live" / name / "cert.pem"
    if not cert.is_file():
        return None
    return x509.load_pem_x509_certificate(cert.read_bytes()).fingerprint(hashes.SHA256()).hex()


def base_args(cfg: Config) -> list[str]:
    le = cfg.letsencrypt_dir
    args = [
        certbot_executable(),
        "--non-interactive",
        "--agree-tos",
        "--no-eff-email",
        "--email", cfg.acme.email,
        "--config-dir", str(le),
        "--work-dir", str(le / "work"),
        "--logs-dir", str(le / "logs"),
    ]
    if cfg.acme.directory_url:
        args += ["--server", cfg.acme.directory_url]
    elif cfg.acme.staging:
        args += ["--staging"]
    kid = env_secret(cfg.acme.eab_kid_env, required=False, what="acme.eab_kid_env")
    hmac = env_secret(cfg.acme.eab_hmac_env, required=False, what="acme.eab_hmac_env")
    if kid and hmac:
        args += ["--eab-kid", kid, "--eab-hmac-key", hmac]
    return args


def certonly_args(cfg: Config, cert: CertificateConfig, *, force: bool, dry_run: bool) -> list[str]:
    args = base_args(cfg) + [
        "certonly",
        "--manual",
        "--preferred-challenges", "dns",
        "--manual-auth-hook", hook_command("auth"),
        "--manual-cleanup-hook", hook_command("cleanup"),
        "--cert-name", cert.name,
        "--key-type", cert.key_type or cfg.acme.key_type,
        "--keep-until-expiring",
        "--renew-with-new-domains",
    ]
    for d in cert.domains:
        args += ["-d", d]
    if force:
        args.append("--force-renewal")
    if dry_run:
        args.append("--dry-run")
    return args


def obtain_or_renew(cfg: Config, cert: CertificateConfig, *, force: bool = False, dry_run: bool = False) -> bool:
    """Führt certbot aus. Liefert True, wenn sich das Zertifikat geändert hat."""
    PendingTxtState(cfg.state_dir).clear()
    cfg.letsencrypt_dir.mkdir(parents=True, exist_ok=True)
    cfg.state_dir.mkdir(parents=True, exist_ok=True)
    before = lineage_fingerprint(cfg, cert.name)
    args = certonly_args(cfg, cert, force=force, dry_run=dry_run)
    # Die Hooks laufen als eigene Prozesse und lesen dieselbe Config/denselben Datenpfad
    env = {
        **os.environ,
        "ACME_HELPER_DATA": str(cfg.data_path),
        "ACME_HELPER_CONFIG": os.environ.get("ACME_HELPER_CONFIG", DEFAULT_CONFIG_PATH),
    }
    log.info("certbot für '%s' (%s)%s", cert.name, ", ".join(cert.domains), " [dry-run]" if dry_run else "")
    log.debug("Aufruf: %s", " ".join(args))
    proc = subprocess.run(args, env=env, capture_output=True, text=True)
    for line in (proc.stdout + proc.stderr).splitlines():
        if line.strip():
            log.info("certbot: %s", line.rstrip())
    if proc.returncode != 0:
        raise CertbotError(f"certbot für '{cert.name}' fehlgeschlagen (Exit {proc.returncode})")
    after = lineage_fingerprint(cfg, cert.name)
    changed = after is not None and after != before
    if dry_run:
        log.info("Dry-Run für '%s' erfolgreich", cert.name)
    elif changed:
        log.info("Zertifikat '%s' neu ausgestellt", cert.name)
    else:
        log.info("Zertifikat '%s' noch gültig, keine Erneuerung", cert.name)
    return changed


def list_lineages(cfg: Config) -> list[str]:
    live = cfg.letsencrypt_dir / "live"
    if not live.is_dir():
        return []
    return sorted(p.name for p in live.iterdir() if p.is_dir() and (p / "cert.pem").exists())

from __future__ import annotations

import logging
import os
from dataclasses import dataclass

from ..config import Config, load_config
from ..dns import provider_for
from ..dns.base import DnsProvider
from ..dns.resolver import challenge_name, follow_cname
from ..logsetup import setup_logging
from ..state import PendingTxtState

log = logging.getLogger(__name__)


@dataclass
class HookContext:
    cfg: Config
    domain: str
    validation: str
    remaining: int
    challenge_fqdn: str
    target_fqdn: str
    provider_name: str
    provider: DnsProvider
    pending: PendingTxtState


def build_context() -> HookContext:
    setup_logging()
    cfg = load_config()
    try:
        domain = os.environ["CERTBOT_DOMAIN"]
        validation = os.environ["CERTBOT_VALIDATION"]
    except KeyError as exc:
        raise SystemExit(f"Hook ohne certbot-Umgebung aufgerufen, fehlt: {exc}")
    remaining = int(os.environ.get("CERTBOT_REMAINING_CHALLENGES", "0") or 0)
    fqdn = challenge_name(domain)
    target = follow_cname(fqdn)
    zone, provider = provider_for(cfg, target)
    log.info(
        "Challenge für %s: %s -> %s (Zone %s, Provider %s), verbleibend: %d",
        domain, fqdn, target, zone.suffix, zone.provider, remaining,
    )
    return HookContext(
        cfg=cfg,
        domain=domain,
        validation=validation,
        remaining=remaining,
        challenge_fqdn=fqdn,
        target_fqdn=target,
        provider_name=zone.provider,
        provider=provider,
        pending=PendingTxtState(cfg.state_dir),
    )

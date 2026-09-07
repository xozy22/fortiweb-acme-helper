"""certbot --manual-auth-hook: TXT setzen, beim letzten Challenge auf Propagation warten."""

from __future__ import annotations

import logging
import sys

from ..dns import propagation_timeout_for
from ..dns.resolver import wait_for_txt
from ..errors import AcmeHelperError
from .common import build_context

log = logging.getLogger(__name__)


def main() -> int:
    try:
        ctx = build_context()
        ctx.provider.add_txt(ctx.target_fqdn, ctx.validation)
        ctx.pending.add(ctx.target_fqdn, ctx.validation, ctx.provider_name)
        if ctx.remaining > 0:
            return 0
        items = ctx.pending.items()
        timeout = max(propagation_timeout_for(ctx.cfg, it["provider"]) for it in items)
        ok = wait_for_txt(
            [(it["fqdn"], it["value"]) for it in items],
            timeout=timeout,
            interval=ctx.cfg.acme.propagation_interval,
        )
        if not ok:
            log.error("TXT-Records nicht rechtzeitig sichtbar, breche Validierung ab")
            return 1
        return 0
    except AcmeHelperError as exc:
        log.error("Auth-Hook fehlgeschlagen: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())

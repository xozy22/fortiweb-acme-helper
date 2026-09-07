"""certbot --manual-cleanup-hook: TXT wieder entfernen. Schlägt nie hart fehl."""

from __future__ import annotations

import logging
import sys

from ..errors import AcmeHelperError
from .common import build_context

log = logging.getLogger(__name__)


def main() -> int:
    try:
        ctx = build_context()
    except (AcmeHelperError, SystemExit) as exc:
        log.error("Cleanup-Hook: Kontext nicht aufbaubar: %s", exc)
        return 0
    try:
        ctx.provider.remove_txt(ctx.target_fqdn, ctx.validation)
    except AcmeHelperError as exc:
        log.warning("Cleanup-Hook: TXT %s konnte nicht entfernt werden: %s", ctx.target_fqdn, exc)
    if ctx.remaining == 0:
        ctx.pending.clear()
    return 0


if __name__ == "__main__":
    sys.exit(main())

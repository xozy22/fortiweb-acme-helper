import logging
import os
import sys


def setup_logging(level: str | None = None) -> None:
    level = (level or os.environ.get("ACME_HELPER_LOG_LEVEL") or "INFO").upper()
    logging.basicConfig(
        level=level,
        stream=sys.stderr,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    for noisy in ("urllib3", "requests", "charset_normalizer"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

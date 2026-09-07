"""Optionale Benachrichtigung per Webhook (generisches JSON-POST)."""

from __future__ import annotations

import logging
import socket
from datetime import datetime, timezone

import requests

from .config import NotifyConfig, env_secret

log = logging.getLogger(__name__)


def notify(cfg: NotifyConfig, *, status: str, message: str, details: dict | None = None) -> None:
    if status == "success" and not cfg.on_success:
        return
    if status == "failure" and not cfg.on_failure:
        return
    url = env_secret(cfg.webhook_url_env, required=False, what="notify.webhook_url_env")
    if not url:
        return
    payload = {
        "source": "acme-helper",
        "host": socket.gethostname(),
        "status": status,
        "message": message,
        # "text" wird von Slack-, Teams- und ntfy-artigen Empfängern direkt angezeigt
        "text": f"[acme-helper] {status.upper()}: {message}",
        "details": details or {},
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    try:
        resp = requests.post(url, json=payload, timeout=15)
        if resp.status_code >= 400:
            log.warning("Webhook antwortete mit %s: %s", resp.status_code, resp.text[:200])
    except requests.RequestException as exc:
        log.warning("Webhook nicht erreichbar: %s", exc)

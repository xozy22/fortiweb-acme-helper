"""Daemon-Schleife: Lauf beim Start, danach täglich zur konfigurierten Uhrzeit."""

from __future__ import annotations

import logging
import signal
import threading
from datetime import datetime, timedelta
from typing import Callable
from zoneinfo import ZoneInfo

from .config import ScheduleConfig

log = logging.getLogger(__name__)


def next_run(now: datetime, schedule: ScheduleConfig) -> datetime:
    tz = ZoneInfo(schedule.timezone)
    local_now = now.astimezone(tz)
    hour, minute = (int(x) for x in schedule.time.split(":"))
    candidate = local_now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if candidate <= local_now:
        candidate += timedelta(days=1)
    return candidate


def run_forever(job: Callable[[], None], schedule: ScheduleConfig) -> None:
    stop = threading.Event()

    def _handler(signum, _frame):
        log.info("Signal %s empfangen, beende nach aktuellem Lauf", signum)
        stop.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, _handler)
        except (ValueError, OSError):
            pass

    while not stop.is_set():
        try:
            job()
        except Exception:  # noqa: BLE001 - Daemon darf nicht sterben
            log.exception("Unerwarteter Fehler im Lauf")
        nxt = next_run(datetime.now(ZoneInfo(schedule.timezone)), schedule)
        wait = max(60.0, (nxt - datetime.now(ZoneInfo(schedule.timezone))).total_seconds())
        log.info("Nächster Lauf: %s (%d min)", nxt.strftime("%Y-%m-%d %H:%M %Z"), wait // 60)
        stop.wait(wait)
    log.info("Scheduler beendet")

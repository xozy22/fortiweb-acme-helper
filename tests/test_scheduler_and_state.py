from datetime import datetime
from zoneinfo import ZoneInfo

from acme_helper.config import ScheduleConfig
from acme_helper.scheduler import next_run
from acme_helper.state import PendingTxtState


def test_next_run_today_and_tomorrow():
    tz = ZoneInfo("Europe/Berlin")
    sched = ScheduleConfig(time="03:30", timezone="Europe/Berlin")
    early = datetime(2026, 9, 7, 1, 0, tzinfo=tz)
    assert next_run(early, sched) == datetime(2026, 9, 7, 3, 30, tzinfo=tz)
    late = datetime(2026, 9, 7, 12, 0, tzinfo=tz)
    assert next_run(late, sched) == datetime(2026, 9, 8, 3, 30, tzinfo=tz)


def test_pending_state_roundtrip(tmp_path):
    p = PendingTxtState(tmp_path)
    assert p.items() == []
    p.add("_acme-challenge.a.de", "v1", "cf")
    p.add("_acme-challenge.a.de", "v2", "cf")
    assert [i["value"] for i in p.items()] == ["v1", "v2"]
    p.clear()
    assert p.items() == []

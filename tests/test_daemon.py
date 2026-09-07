"""Daemon darf bei ungültiger Konfiguration nicht beenden (Restart-Schleife im Container)."""

import pytest

from acme_helper import cli
from acme_helper.errors import ConfigError


def test_daemon_survives_invalid_config(monkeypatch):
    attempts = {"n": 0}

    def fake_load(_path=None):
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise ConfigError("kaputt")
        raise SystemExit("config ok, wir stoppen den Test hier")

    monkeypatch.setattr(cli, "load_config", fake_load)
    monkeypatch.setattr(cli, "CONFIG_RETRY_SECONDS", 0)
    with pytest.raises(SystemExit, match="config ok"):
        cli.main(["run"])
    assert attempts["n"] == 3  # zweimal ungültig, beim dritten Mal weiter


def test_force_renew_only_first_run(monkeypatch):
    calls: list[bool] = []

    class Cfg:
        schedule = None

    monkeypatch.setattr(cli, "load_config", lambda _p=None: Cfg())
    monkeypatch.setattr(cli, "run_once", lambda cfg, **kw: calls.append(kw["force_renew"]) or 0)

    def fake_forever(job, schedule):
        job()
        job()

    monkeypatch.setattr(cli, "run_forever", fake_forever)
    assert cli.main(["run", "--force-renew"]) == 0
    assert calls == [True, False]


def test_once_mode_exits_on_invalid_config(monkeypatch):
    monkeypatch.setattr(cli, "load_config", lambda _p=None: (_ for _ in ()).throw(ConfigError("kaputt")))
    assert cli.main(["run", "--once"]) == 2

import copy

import pytest

from acme_helper.config import Config, env_secret
from acme_helper.errors import ConfigError
from tests.conftest import BASE_CONFIG


def test_valid_config(cfg):
    assert cfg.certificates[0].deploy[0].fortiweb == "fw1"
    assert cfg.zones[0].suffix == "example.com"


def test_unknown_provider_in_zone():
    data = copy.deepcopy(BASE_CONFIG)
    data["zones"].append({"suffix": "x.de", "provider": "nope"})
    with pytest.raises(ValueError, match="nope"):
        Config.model_validate(data)


def test_unknown_fortiweb_in_deploy():
    data = copy.deepcopy(BASE_CONFIG)
    data["certificates"][0]["deploy"][0]["fortiweb"] = "fw9"
    with pytest.raises(ValueError, match="fw9"):
        Config.model_validate(data)


def test_duplicate_prefix_same_fortiweb():
    data = copy.deepcopy(BASE_CONFIG)
    second = copy.deepcopy(data["certificates"][0])
    second["name"] = "other"
    data["certificates"].append(second)
    with pytest.raises(ValueError, match="cert_name_prefix"):
        Config.model_validate(data)


def test_env_secret_missing(monkeypatch):
    monkeypatch.delenv("NOPE", raising=False)
    with pytest.raises(ConfigError, match="NOPE"):
        env_secret("NOPE", what="test")
    assert env_secret("NOPE", required=False) is None

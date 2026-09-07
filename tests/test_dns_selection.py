from acme_helper.config import ZoneConfig
from acme_helper.dns import match_zone
from acme_helper.dns.resolver import challenge_name


def test_challenge_name():
    assert challenge_name("example.com") == "_acme-challenge.example.com"
    assert challenge_name("*.example.com") == "_acme-challenge.example.com"
    assert challenge_name("Sub.Example.COM.") == "_acme-challenge.sub.example.com"


def test_match_zone_longest_suffix():
    zones = [
        ZoneConfig(suffix="example.net", provider="a"),
        ZoneConfig(suffix="acme.example.net", provider="b"),
    ]
    assert match_zone("_acme-challenge.foo.de.acme.example.net", zones).provider == "b"
    assert match_zone("_acme-challenge.example.net", zones).provider == "a"
    assert match_zone("example.net", zones).provider == "a"
    assert match_zone("notexample.net", zones) is None

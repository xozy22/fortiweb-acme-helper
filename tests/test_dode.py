import pytest
import responses

from acme_helper.config import DodeProvider
from acme_helper.dns.dode import DodeDns
from acme_helper.errors import DnsError

URL = "https://my.do.de/api/letsencrypt"


@responses.activate
def test_add_txt_success(env):
    responses.get(URL, body='{"success":true}',
                  match=[responses.matchers.query_param_matcher(
                      {"token": "dode-token", "domain": "_acme-challenge.x.de.acme.example.net", "value": "v1"})])
    DodeDns("dode", DodeProvider(type="dode", token_env="DODE_TOKEN")).add_txt(
        "_acme-challenge.x.de.acme.example.net", "v1")


@responses.activate
def test_add_txt_failure_hides_token(env):
    responses.get(URL, body='{"success":false,"error":"bad token dode-token"}')
    with pytest.raises(DnsError) as exc:
        DodeDns("dode", DodeProvider(type="dode", token_env="DODE_TOKEN")).add_txt("_acme-challenge.x.de", "v")
    assert "dode-token" not in str(exc.value)


@responses.activate
def test_remove_txt_uses_delete_action(env):
    call = responses.get(URL, body="success",
                         match=[responses.matchers.query_param_matcher(
                             {"token": "dode-token", "domain": "_acme-challenge.x.de", "action": "delete"})])
    DodeDns("dode", DodeProvider(type="dode", token_env="DODE_TOKEN")).remove_txt("_acme-challenge.x.de", "v")
    assert call.call_count == 1

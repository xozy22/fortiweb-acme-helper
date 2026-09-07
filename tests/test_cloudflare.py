import responses

from acme_helper.config import CloudflareProvider
from acme_helper.dns.cloudflare import CloudflareDns

API = "https://api.cloudflare.com/client/v4"


def _provider():
    return CloudflareDns("cf", CloudflareProvider(type="cloudflare", api_token_env="CF_API_TOKEN"))


@responses.activate
def test_add_and_remove_txt(env):
    # Zone-Suche: erst der volle Name (leer), dann example.com (Treffer)
    responses.get(f"{API}/zones", json={"success": True, "result": []},
                  match=[responses.matchers.query_param_matcher({"name": "_acme-challenge.example.com", "status": "active"})])
    responses.get(f"{API}/zones", json={"success": True, "result": [{"id": "z1"}]},
                  match=[responses.matchers.query_param_matcher({"name": "example.com", "status": "active"})])
    # Noch kein Record vorhanden
    responses.get(f"{API}/zones/z1/dns_records", json={"success": True, "result": []})
    post = responses.post(f"{API}/zones/z1/dns_records", json={"success": True, "result": {"id": "r1"}})

    p = _provider()
    p.add_txt("_acme-challenge.example.com", "abc")
    assert post.call_count == 1
    assert responses.calls[-1].request.headers["Authorization"] == "Bearer cf-token"

    responses.replace(responses.GET, f"{API}/zones/z1/dns_records",
                      json={"success": True, "result": [{"id": "r1", "content": "\"abc\""}, {"id": "r2", "content": "other"}]})
    delete = responses.delete(f"{API}/zones/z1/dns_records/r1", json={"success": True, "result": {"id": "r1"}})
    p.remove_txt("_acme-challenge.example.com", "abc")
    assert delete.call_count == 1

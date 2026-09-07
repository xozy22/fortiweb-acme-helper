import responses

from acme_helper.config import StratoProvider
from acme_helper.dns.strato import StratoDns, TxtRecord

API = "https://www.strato.de/apps/CustomerService"

LOGIN_2FA_HTML = """
<html><body><h1>Zwei-Faktor-Authentifizierung</h1>
<form><input type="hidden" name="totp_token" value="tok123">
<select name="pw_id"><option value="7">Handy (acme-helper)</option><option value="8">Tablet</option></select>
</form></body></html>
"""

PACKAGES_HTML = """
<html><body><table id="package_list"><tbody>
<tr><td class="package-information">PowerWeb Basic legacy-strato.de weitere</td>
    <td class="jss_with_own_packagename"><a href="?sessionID=S1&cID=4711&node=x">Verwalten</a></td></tr>
<tr><td class="package-information">Hosting other.de</td>
    <td class="jss_with_own_packagename"><a href="?sessionID=S1&cID=99&node=x">Verwalten</a></td></tr>
</tbody></table></body></html>
"""

RECORDS_HTML = """
<html><body><form>
<div class="txt-record-tmpl">
  <input name="prefix" value="">
  <select name="type"><option value="TXT" selected>TXT</option><option value="CNAME">CNAME</option></select>
  <textarea name="value">v=spf1 -all</textarea>
</div>
<div class="txt-record-tmpl">
  <input name="prefix" value="_acme-challenge">
  <select name="type"><option value="TXT" selected>TXT</option></select>
  <textarea name="value">old-value</textarea>
</div>
</form></body></html>
"""


def _register_login(with_2fa: bool):
    responses.get(API, body="<html>login</html>")
    if with_2fa:
        responses.post(API, body=LOGIN_2FA_HTML)  # erster POST: Passwort -> 2FA-Seite
        responses.post(API, status=302, headers={"Location": f"{API}?sessionID=S1&cID=0"})
    else:
        responses.post(API, status=302, headers={"Location": f"{API}?sessionID=S1&cID=0"})
    responses.get(API, body="<html>start</html>",
                  match=[responses.matchers.query_param_matcher({"sessionID": "S1", "cID": "0"})])
    responses.get(API, body=PACKAGES_HTML,
                  match=[responses.matchers.query_param_matcher({"sessionID": "S1", "cID": "0", "node": "kds_CustomerEntryPage"})])
    responses.get(API, body=RECORDS_HTML,
                  match=[responses.matchers.query_param_matcher(
                      {"sessionID": "S1", "cID": "4711", "node": "ManageDomains", "action_show_txt_records": "", "vhost": "legacy-strato.de"})])


@responses.activate
def test_add_txt_with_2fa(env, monkeypatch, tmp_path):
    monkeypatch.setenv("STRATO_TOTP_SECRET", "JBSWY3DPEHPK3PXP")
    _register_login(with_2fa=True)
    push = responses.post(API, body="ok")

    p = StratoDns("strato", StratoProvider(type="strato", username_env="STRATO_USER", password_env="STRATO_PASS",
                                          totp_secret_env="STRATO_TOTP_SECRET", totp_devicename="acme-helper"),
                  debug_dir=tmp_path)
    p.add_txt("_acme-challenge.legacy-strato.de", "new-value")

    # 2FA-POST enthält Gerät 7 und ein TOTP
    twofa = [c for c in responses.calls if c.request.method == "POST"][1]
    assert "pw_id=7" in twofa.request.body and "totp_token=tok123" in twofa.request.body
    # Letzter POST: kompletter Record-Satz inkl. altem SPF und beiden ACME-Werten
    body = push.calls[0].request.body
    assert body.count("prefix=") == 3
    assert "v%3Dspf1+-all" in body and "old-value" in body and "new-value" in body
    assert "cID=4711" in body and "vhost=legacy-strato.de" in body


@responses.activate
def test_remove_txt_keeps_other_records(env, tmp_path):
    _register_login(with_2fa=False)
    push = responses.post(API, body="ok")
    p = StratoDns("strato", StratoProvider(type="strato", username_env="STRATO_USER", password_env="STRATO_PASS"),
                  debug_dir=tmp_path)
    p.remove_txt("_acme-challenge.legacy-strato.de", "old-value")
    body = push.calls[0].request.body
    assert body.count("prefix=") == 1  # nur der SPF-Record bleibt
    assert "old-value" not in body and "spf1" in body


@responses.activate
def test_locate_subdomain(env, tmp_path):
    _register_login(with_2fa=False)
    p = StratoDns("strato", StratoProvider(type="strato", username_env="STRATO_USER", password_env="STRATO_PASS"))
    c = p.client()
    assert c.locate("_acme-challenge.app.legacy-strato.de") == ("4711", "legacy-strato.de", "_acme-challenge.app")


def test_txtrecord_dataclass():
    r = TxtRecord(prefix="_acme-challenge", type="TXT", value="x")
    assert r.prefix == "_acme-challenge"

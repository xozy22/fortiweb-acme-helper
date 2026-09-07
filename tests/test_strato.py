import pytest
import responses

from acme_helper.config import StratoProvider
from acme_helper.dns.strato import StratoClient, StratoDns, TxtRecord

API = "https://www.strato.de/apps/CustomerService"

# Echte Struktur der Login-Seite (Stand 09/2026): Action mit sessionID, verstecktes Feld, Submit-Name
LOGIN_HTML = """
<html><head><title>STRATO Kunden-Login</title></head><body>
<form id="ksbLogin" method="post" action="/apps/CustomerService?sessionID=S0">
  <input type="text" name="identifier" placeholder="Benutzername oder Kundennummer">
  <input type="password" name="passwd">
  <input type="hidden" name="login_success_query_params" value="x=1">
  <input type="submit" name="action_customer_login.x" value="Login">
</form>
<form name="reset_password_form" action="/apps/ChangePassword" method="post">
  <input type="text" name="identifier"><input type="email" name="email">
</form>
</body></html>
"""


@pytest.fixture(autouse=True)
def _no_login_delay(monkeypatch):
    monkeypatch.setattr(StratoClient, "login_delay", 0)


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
    responses.get(API, body=LOGIN_HTML)
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

    # Login-POST geht an die Form-Action (mit sessionID) und enthält das versteckte Feld
    login_post = [c for c in responses.calls if c.request.method == "POST"][0]
    assert login_post.request.url == f"{API}?sessionID=S0"
    assert "login_success_query_params=x%3D1" in login_post.request.body
    assert "identifier=12345" in login_post.request.body and "action_customer_login.x=Login" in login_post.request.body
    assert login_post.request.headers["Referer"] == API
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


@responses.activate
def test_login_page_returned_again_is_failure(env, tmp_path):
    """Strato antwortet bei falschen Daten mit HTTP 200 und derselben Login-Seite."""
    responses.get(API, body=LOGIN_HTML)
    responses.post(API, body=LOGIN_HTML)
    p = StratoDns("strato", StratoProvider(type="strato", username_env="STRATO_USER", password_env="STRATO_PASS"),
                  debug_dir=tmp_path)
    with pytest.raises(Exception, match="Kundennummer statt E-Mail"):
        p.client()
    assert list(tmp_path.glob("strato-login-*.html"))


def test_txtrecord_dataclass():
    r = TxtRecord(prefix="_acme-challenge", type="TXT", value="x")
    assert r.prefix == "_acme-challenge"

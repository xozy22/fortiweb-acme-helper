# Strato einrichten

Strato hat keine DNS-API. Es gibt zwei Wege, und der erste ist der empfohlene:

| Weg | Was passiert | Zugangsdaten im Container | Robustheit |
|---|---|---|---|
| **A: CNAME-Delegation** | Einmalig bei Strato ein CNAME-Record. Die TXT-Records landen bei Cloudflare oder do.de | keine Strato-Daten | hoch |
| **B: Web-Login** | acme-helper meldet sich im Strato-Kundenlogin an und setzt die TXT-Records über die Oberfläche | Kundennummer, Passwort, ggf. TOTP | bricht, sobald Strato die Oberfläche ändert |

Beide Wege lassen sich mischen: Domain X per Delegation, Domain Y per Web-Login.

## Weg A: CNAME-Delegation (empfohlen)

### Prinzip

Let's Encrypt fragt bei der Validierung `_acme-challenge.strato-domain.de` als TXT ab. Steht dort ein CNAME, folgt
Let's Encrypt ihm und liest den TXT-Wert am Ziel. Das Ziel kann in jeder Zone liegen, die per API bedienbar ist.

```
_acme-challenge.strato-domain.de.   CNAME   _acme-challenge.strato-domain.de.acme.example.com.
                                              └── liegt bei Cloudflare oder do.de, dort schreibt acme-helper
```

Der Zielname ist frei wählbar. Bewährt hat sich `<challenge-name>.<delegationszone>`, weil so mehrere
Strato-Domains ohne Kollisionen in eine Zone delegiert werden können.

### 1. Zielzone festlegen

Eine Zone, die bei Cloudflare oder do.de liegt, z.B. `example.com`. Es muss nichts vorbereitet werden; die
TXT-Records werden bei jeder Ausstellung neu angelegt und wieder gelöscht.

### 2. CNAME bei Strato setzen

1. Kundenlogin <https://www.strato.de/apps/CustomerService> → **Domains** → **Domainverwaltung**.
2. Bei der Domain auf das Zahnrad → Reiter **DNS**.
3. Abschnitt **TXT- und CNAME-Records verwalten** → **verwalten**.
4. Neuen Eintrag anlegen:
   - **Präfix:** `_acme-challenge` (Strato hängt den Domainnamen automatisch an)
   - **Typ:** `CNAME`
   - **Wert:** `_acme-challenge.strato-domain.de.acme.example.com` (ohne Punkt am Ende)
5. **Einstellung übernehmen**.

Lässt die Maske für den Präfix keinen CNAME zu, alternativ unter **Subdomains anzeigen** die Subdomain
`_acme-challenge` anlegen, dort **DNS-Verwaltung** → **CNAME-Record** → **verwalten** und das Ziel eintragen.
Strato erlaubt CNAMEs nur auf Subdomains, was hier genau passt.

### 3. Warten und prüfen

Strato-Änderungen brauchen erfahrungsgemäß Minuten bis zu einer Stunde, offiziell bis zu 24 Stunden. Prüfen:

```bash
dig _acme-challenge.strato-domain.de CNAME +short
# erwartet: _acme-challenge.strato-domain.de.acme.example.com.
```

### 4. acme-helper konfigurieren

Für die Strato-Domain wird **kein** Strato-Provider gebraucht. Nur die Zielzone muss in `zones` stehen:

**Unraid / Env-Modus:** `CF_API_TOKEN` (oder `DODE_TOKEN`) und `ZONES=example.com=cf`,
`CERT1_DOMAINS=strato-domain.de,*.strato-domain.de`.

**YAML-Modus:**

```yaml
zones:
  - { suffix: example.com, provider: cf }     # deckt auch *.acme.example.com ab
certificates:
  - name: wildcard-strato
    domains: ["strato-domain.de", "*.strato-domain.de"]
```

`acme-helper check` zeigt dann `_acme-challenge.strato-domain.de -> _acme-challenge.strato-domain.de.acme.example.com => cf`.

### 5. Testen

```bash
acme-helper dns-test strato-domain.de
```

Der Test folgt dem CNAME, setzt den TXT bei Cloudflare/do.de und prüft die Sichtbarkeit am Ziel.

## Weg B: Strato-Web-Login automatisieren

acme-helper nutzt die Mechanik des Projekts [Buxdehuda/strato-certbot](https://github.com/Buxdehuda/strato-certbot):
Anmeldung im Kundenlogin, Paket der Domain ermitteln, die Liste der TXT-/CNAME-Records lesen, den
Challenge-Eintrag ergänzen und die komplette Liste zurückschreiben.

### Was du brauchst

- **Kundennummer** oder **Benutzername** und das **Passwort** des Strato-Kontos. Das Login-Feld heißt bei Strato
  „Benutzername oder Kundennummer“; die E-Mail-Adresse funktioniert dort **nicht**. Die Kundennummer steht oben
  im Kundenlogin und auf jeder Rechnung.
- Falls Zwei-Faktor-Authentifizierung aktiv ist: das **TOTP-Secret** (Base32-String) und den **Gerätenamen**,
  wie er im Strato-Login in der Geräteauswahl erscheint.

Empfehlung: Ein eigenes TOTP-Gerät nur für acme-helper anlegen. Beim Einrichten unter
**Mein Konto → Sicherheit → Zwei-Faktor-Authentifizierung** zeigt Strato einen QR-Code; der Base32-Schlüssel
dahinter ist das Secret. Gerätename z.B. `acme-helper`.

### Konfiguration

**Unraid / Env-Modus:** `STRATO_USER`, `STRATO_PASS`, optional `STRATO_TOTP_SECRET` und
`STRATO_TOTP_DEVICENAME`, dazu `ZONES=strato-domain.de=strato`.

**YAML-Modus:**

```yaml
dns_providers:
  strato:
    type: strato
    username_env: STRATO_USER
    password_env: STRATO_PASS
    totp_secret_env: STRATO_TOTP_SECRET     # weglassen ohne 2FA
    totp_devicename: acme-helper
    propagation_timeout: 900                # Strato ist langsam
zones:
  - { suffix: strato-domain.de, provider: strato }
```

Für Strato-Kunden außerhalb Deutschlands `api_url` anpassen (z.B. `https://www.strato.nl/apps/CustomerService`).

### Testen

```bash
acme-helper check --probe        # führt einen echten Login aus und listet die Pakete
acme-helper dns-test strato-domain.de --timeout 900
```

### Einschränkungen

- Jeder Aufruf ist ein Login. Bei Wildcard + Basisdomain sind das zwei Logins zum Setzen und zwei zum Löschen.
- Die Oberfläche ist nicht stabil. Ändert Strato Formularnamen oder Selektoren, schlägt der Provider fehl. Das
  zuletzt gesehene HTML liegt dann unter `/data/debug/strato-*.html` (Unraid:
  `/mnt/user/appdata/acme-helper/data/debug/`). Damit lassen sich die Selektoren in
  `src/acme_helper/dns/strato.py` anpassen.
- Die komplette Record-Liste wird zurückgeschrieben. acme-helper liest sie vorher ein und ergänzt nur; trotzdem
  vorher ein Backup der TXT-Einträge (SPF, DKIM, Verifizierungen) machen.
- Propagation dauert bei Strato länger, deshalb 900 s Timeout.

## Fehlerbilder

| Meldung | Ursache |
|---|---|
| `Strato-Login fehlgeschlagen (keine sessionID ...)` | Zugangsdaten falsch, Captcha nach zu vielen Fehlversuchen, oder Login-Seite geändert |
| `Strato verlangt 2FA, aber es ist kein totp_secret konfiguriert` | Konto hat 2FA, Secret fehlt |
| `kein Paket enthält eine Domain für ...` | Domain liegt in einem anderen Strato-Konto oder die Paketliste wurde nicht erkannt |
| `Timeout beim Propagation-Check` | Strato hat noch nicht publiziert; `propagation_timeout` erhöhen oder auf Weg A wechseln |
| Weg A: `keine Zone in 'zones' passt zu _acme-challenge.strato-domain.de.acme.example.com` | Delegationszone fehlt in `zones` |

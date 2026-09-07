# acme-helper – DNS-01-Zertifikate für FortiWeb

> **Disclaimer / Haftungsausschluss**
>
> Dies ist ein unabhängiges Community-Projekt und **kein offizielles Tool von Fortinet**. Es wird weder von
> Fortinet entwickelt, unterstützt noch geprüft. „Fortinet“ und „FortiWeb“ sind Marken der Fortinet, Inc.
> Ebenso besteht keine Verbindung zu Strato, Domain-Offensive (do.de), Cloudflare oder Let's Encrypt.
>
> Die Software wird ohne Gewähr bereitgestellt (siehe [LICENSE](LICENSE)). Sie greift schreibend auf DNS-Zonen
> und auf die Konfiguration einer Web Application Firewall zu. Teste sie zuerst mit `acme.staging: true` gegen
> eine nicht produktive Umgebung und prüfe die Ergebnisse, bevor du sie produktiv einsetzt.
>
> *This is an independent community project and **not an official Fortinet tool**. It is not developed,
> supported or endorsed by Fortinet. Use at your own risk.*

FortiWeb kann Let's-Encrypt-Zertifikate über ACME holen, muss bei DNS-01 den TXT-Record aber jedes Mal
manuell beim DNS-Provider gesetzt bekommen. Wildcard-Zertifikate brauchen zwingend DNS-01, damit ist
die automatische Erneuerung in FortiWeb faktisch nicht möglich.

Dieser Container übernimmt die komplette ACME-Rolle:

1. **certbot** holt und erneuert die Zertifikate (Account, Renewal-Logik, Staging/Produktion).
2. Eigene Hooks setzen die TXT-Records bei **Cloudflare**, **do.de** und **Strato** und warten, bis die
   Records auf den autoritativen Nameservern sichtbar sind.
3. Das fertige Zertifikat wird per **FortiWeb-REST-API** hochgeladen, an Server-Policies und
   SNI-Einträge gebunden, verifiziert, und alte Versionen werden aufgeräumt.

FortiWeb ist danach nur noch Konsument. Der Deploy hängt nicht an einem certbot-Hook, sondern läuft
als Abgleich über den Zertifikats-Fingerprint: ein fehlgeschlagener Upload wird beim nächsten Lauf
automatisch nachgeholt.

```
acme-helper run [--once]
  1. certbot certonly --keep-until-expiring   (pro Zertifikat; Hooks -> Cloudflare / do.de / Strato)
  2. Reconcile: Fingerprint der Lineage != deployed.json?  -> FortiWeb: import -> chain -> bind -> verify -> cleanup
  3. Warten bis zum nächsten Lauf (Daemon) bzw. Ende (--once)
```

## Anleitungen

| Thema | Dokument |
|---|---|
| Cloudflare: API-Token anlegen, prüfen, eintragen | [docs/providers/cloudflare.md](docs/providers/cloudflare.md) |
| do.de: Let's-Encrypt-Token im Kundenportal, Besonderheiten der API | [docs/providers/dode.md](docs/providers/dode.md) |
| Strato: CNAME-Delegation (empfohlen) oder Web-Login mit TOTP | [docs/providers/strato.md](docs/providers/strato.md) |
| FortiWeb: Admin, Trusted Host, TLS, Server Policy und SNI, Firmware-Abweichungen | [docs/providers/fortiweb.md](docs/providers/fortiweb.md) |
| Unraid: Template importieren, Variablen, erster Start | [Abschnitt Unraid](#unraid) |

## Schnellstart

```bash
cp .env.example .env                          # Secrets eintragen
cp config/config.example.yaml config/config.yaml
docker compose build
docker compose run --rm acme-helper check     # Config, Provider, FortiWeb-Verbindung
docker compose run --rm acme-helper run --once --dry-run   # certbot-Dry-Run gegen Staging
docker compose run --rm acme-helper run --once             # echter Lauf (Staging, solange acme.staging: true)
docker compose up -d                          # Daemon, täglich zur konfigurierten Uhrzeit
```

Wenn alles funktioniert: `acme.staging: false` setzen und einmal `run --once --force-renew` ausführen,
damit ein Produktionszertifikat ausgestellt und deployt wird.

## Unraid

acme-helper ist für Unraid als Community-Applications-Template ausgelegt: [unraid/acme-helper.xml](unraid/acme-helper.xml).
Alle Einstellungen inklusive Secrets werden als Variablen direkt in der Unraid-Oberfläche gesetzt, eine
`config.yaml` ist nicht nötig. Das Image `ghcr.io/xozy22/fortiweb-acme-helper:latest` wird per GitHub Actions
für amd64 und arm64 gebaut und ist ohne Login abrufbar.

### Voraussetzungen

- Unraid 6.10 oder neuer mit Docker-Dienst.
- Die FortiWeb muss vom Unraid-Host aus auf dem Admin-Port (Standard 8443) erreichbar sein, und die Unraid-IP
  muss bei dem FortiWeb-Admin als Trusted Host eingetragen sein.
- Zugangsdaten für mindestens einen DNS-Provider (Cloudflare-API-Token, do.de-Token oder Strato-Login).
- Für Strato-Domains am besten vorab die CNAME-Delegation einrichten (siehe [Strato-Anleitung](docs/providers/strato.md)).
- Schritt-für-Schritt-Anleitungen je Provider: [Cloudflare](docs/providers/cloudflare.md),
  [do.de](docs/providers/dode.md), [Strato](docs/providers/strato.md), [FortiWeb](docs/providers/fortiweb.md).

### Template importieren

**Weg 1: Template-Repository (empfohlen)**

1. *Apps* öffnen, dort *Settings* (Zahnrad oben rechts).
2. Unter *Template repositories* die URL `https://github.com/xozy22/fortiweb-acme-helper` eintragen und *Save* klicken.
3. In *Apps* nach `acme-helper` suchen und *Install* wählen.

**Weg 2: Template-Datei auf den USB-Stick**

1. Die Datei [unraid/acme-helper.xml](unraid/acme-helper.xml) herunterladen.
2. Über die Freigabe `flash` nach `/boot/config/plugins/dockerMan/templates-user/acme-helper.xml` kopieren.
3. *Docker → Add Container* öffnen und im Dropdown *Template* den Eintrag `acme-helper` auswählen.

### Variablen ausfüllen

Die Maske zeigt zunächst die Pflichtfelder; *Show more settings* blendet die restlichen ein.

| Feld | Was eintragen |
|---|---|
| ACME e-mail | Kontaktadresse für den Let's-Encrypt-Account |
| ACME staging | `true` lassen, bis alles funktioniert |
| Cloudflare / do.de / Strato | nur die Provider befüllen, die du nutzt; leere Felder werden ignoriert |
| Zones | `suffix=provider`, z.B. `example.com=cf;acme.example.net=dode`. Bei nur einem Provider optional |
| FortiWeb host / port / user / password | Admin-Zugang mit REST-API-Recht |
| FortiWeb verify TLS | `false`, oder Pfad zu einem CA-Bundle, das du unter `/mnt/user/appdata/acme-helper/config/` ablegst |
| Cert 1: domains | z.B. `example.com,*.example.com` |
| Cert 1: server policies | Namen der Server-Policies, deren Zertifikat gesetzt werden soll |
| Cert 1: SNI bindings | optional, z.B. `sni-main:*.example.com\|example.com` |
| Notification webhook | optional, z.B. ntfy-Topic oder Slack/Teams-Webhook |

Weitere Zertifikate: *Cert 2* ist im Template vorgesehen. Für noch mehr im Container-Dialog unter
*Add another Path, Port, Variable* die Variablen `CERT3_DOMAINS`, `CERT3_POLICIES` usw. anlegen.

`PUID`/`PGID` stehen auf 99/100 (nobody:users), damit `/mnt/user/appdata/acme-helper/data` mit den üblichen
Unraid-Rechten beschrieben wird. Der Entrypoint setzt die Rechte beim Start.

### Erster Start und Freigabe für Produktion

1. Container starten. Er führt sofort einen Lauf aus und danach täglich um `SCHEDULE_TIME` (Standard 03:30, Zeitzone `TZ`).
2. Im Docker-Tab auf das Container-Icon klicken und *Console* öffnen. Dort prüfen:

   ```bash
   acme-helper check --probe
   ```

   `check` zeigt Provider-Zugang, die CNAME-Auflösung jeder Domain, den FortiWeb-Login sowie ob Policies und
   SNI-Gruppen existieren. `--probe` testet zusätzlich den Strato-Login und alle FortiWeb-Endpunkte.
3. `acme-helper list` zeigt, ob das Staging-Zertifikat ausgestellt und auf die FortiWeb gebracht wurde. Das
   Container-Log (*Logs* im Docker-Tab) enthält die certbot-Ausgabe und jeden Deploy-Schritt.
4. Wenn alles passt: Variable *ACME staging* auf `false` stellen, Container speichern (Unraid startet ihn neu)
   und einmal ein Produktionszertifikat erzwingen:

   ```bash
   acme-helper run --once --force-renew
   ```

### Betrieb auf Unraid

- **Backup:** `/mnt/user/appdata/acme-helper/data` enthält Let's-Encrypt-Account, Zertifikate und den
  Deploy-Zustand. Mit dem Appdata-Backup-Plugin sichern.
- **Update:** Über *Docker → Check for Updates* wie bei jedem Container. Versionierte Tags (`0.1.0`, `0.1`)
  stehen alternativ zu `latest` zur Verfügung.
- **Nur Zertifikate holen:** *FortiWeb host* leer lassen, dann werden die Zertifikate nur unter
  `/mnt/user/appdata/acme-helper/data/letsencrypt/live/` abgelegt.
- **Mehrere FortiWebs oder Sonderfälle:** Eine `config.yaml` unter `/mnt/user/appdata/acme-helper/config/`
  hat Vorrang vor den Variablen und erlaubt alle Optionen aus [config/config.example.yaml](config/config.example.yaml).
- **Fehlersuche:** *Log level* auf `DEBUG` stellen. Bei Strato-Problemen liegt das zuletzt gesehene HTML unter
  `/mnt/user/appdata/acme-helper/data/debug/`.

### Netzwerkdiagnose aus der Konsole

Das Image enthält `curl`, `ping`, `ip`, `dig`/`nslookup`, `nc`, `traceroute`, `openssl`, `ps`, `less` und `nano`.
Der schnellste Einstieg ist das eingebaute Kommando, das den kompletten Weg zur FortiWeb prüft:

```bash
acme-helper diag
```

Es zeigt den Resolver des Containers, die Auflösung von Let's Encrypt und Cloudflare, für jede FortiWeb DNS,
TCP-Erreichbarkeit, TLS-Version, Zertifikat (Subject, Issuer, Ablauf, SAN), ob die Zertifikatsprüfung mit der
aktuellen `verify_tls`-Einstellung durchgeht, und ob der API-Login klappt. Zum Schluss die Challenge-Auflösung
jeder Domain mit Zone, Nameservern und zuständigem Provider. Ein beliebiges anderes Ziel geht mit
`acme-helper diag --host 10.0.0.5 --port 8443`.

Manuell, falls es tiefer gehen soll:

```bash
ip -brief addr                                   # IP des Containers (bridge: 172.17.x.x)
ping -c 3 10.0.0.5                               # FortiWeb erreichbar?
nc -zv 10.0.0.5 8443                             # Admin-Port offen?
traceroute -n 10.0.0.5                           # Weg dorthin (VLAN/Firewall dazwischen?)
openssl s_client -connect 10.0.0.5:8443 -servername fortiweb </dev/null | head -20   # TLS-Handshake und Zertifikat
curl -vk https://10.0.0.5:8443/api/v2.0/system/certificate.local \
  -H "Authorization: $(printf '{"username":"%s","password":"%s","vdom":"root"}' "$FW_USER" "$FW_PASS" | base64 -w0)"
dig _acme-challenge.example.com CNAME +short     # CNAME-Delegation korrekt?
dig @1.1.1.1 _acme-challenge.example.com TXT +short
```

Antwortet die FortiWeb mit `403`, ist meist der Trusted Host des Admins nicht auf die Unraid-IP gesetzt.
Kommt gar keine Verbindung zustande, liegt es in der Regel am Docker-Netzwerk (bridge kann das Unraid-Host-Netz
nicht immer erreichen, dann `br0` mit eigener IP verwenden) oder an einer Firewall zwischen Unraid und Management-VLAN.

### Env-Modus (Unraid, Portainer, `docker run`)

Ist keine `/config/config.yaml` vorhanden und `ACME_EMAIL` gesetzt, baut der Container die Konfiguration aus
Variablen. `acme-helper show-config` zeigt das Ergebnis (nur Variablennamen, keine Secret-Werte).

| Variable | Bedeutung |
|---|---|
| `ACME_EMAIL`, `ACME_STAGING`, `ACME_KEY_TYPE`, `ACME_PROPAGATION_TIMEOUT`, `ACME_DIRECTORY_URL` | ACME-Einstellungen; `ACME_STAGING=true` zum Testen |
| `CF_API_TOKEN` | aktiviert Provider `cf` |
| `DODE_TOKEN` | aktiviert Provider `dode` |
| `STRATO_USER`, `STRATO_PASS`, `STRATO_TOTP_SECRET`, `STRATO_TOTP_DEVICENAME` | aktiviert Provider `strato` |
| `ZONES` | `suffix=provider`, getrennt durch `;` oder `,`. Beispiel `example.com=cf;acme.example.net=dode`. Bei genau einem Provider optional |
| `FW_HOST`, `FW_PORT`, `FW_USER`, `FW_PASS`, `FW_VDOM`, `FW_VERIFY_TLS`, `FW_IMPORT_METHOD`, `FW_BODY_WRAPPER` | FortiWeb-Ziel `fw1`; ohne `FW_HOST` werden nur Zertifikate geholt |
| `CERT1_DOMAINS` | Pflicht, kommagetrennt, z.B. `example.com,*.example.com` |
| `CERT1_PREFIX`, `CERT1_POLICIES`, `CERT1_SNI`, `CERT1_CHAIN_MODE`, `CERT1_KEEP_OLD`, `CERT1_NAME`, `CERT1_KEY_TYPE` | Deploy-Optionen; `CERT1_SNI` im Format `gruppe:muster\|muster;gruppe2` |
| `CERT2_*`, `CERT3_*`, ... | weitere Zertifikate, gleiche Felder |
| `SCHEDULE_TIME`, `TZ` | täglicher Lauf |
| `NOTIFY_WEBHOOK`, `NOTIFY_ON_SUCCESS`, `NOTIFY_ON_FAILURE` | Benachrichtigung |
| `PUID`, `PGID` | Besitzer von `/data` |

## Kommandos

| Kommando | Zweck |
|---|---|
| `run` | Daemon: Lauf beim Start, danach täglich zu `schedule.time` |
| `run --once [--force-renew] [--dry-run] [--cert NAME]` | Einzellauf, z.B. für Host-Cron oder Kubernetes CronJob |
| `check [--probe]` | Config validieren, Provider-Secrets, CNAME-Auflösung je Domain, FortiWeb-Login, Policies/SNI-Gruppen. `--probe` testet zusätzlich den Strato-Login und alle FortiWeb-Endpunkte |
| `deploy NAME [--force]` | Vorhandene Lineage (erneut) auf alle konfigurierten FortiWebs bringen |
| `dns-test DOMAIN [--keep]` | Test-TXT über den ermittelten Provider setzen, autoritativ prüfen, wieder löschen |
| `list` | Status aller Zertifikate und Deployments |
| `show-config` | Effektive Konfiguration (aus Datei oder Env-Variablen) ohne Secret-Werte |
| `diag [--host H --port P]` | Netzwerkdiagnose: Resolver, FortiWeb (DNS, TCP, TLS, Verify, API-Login), Challenge-Auflösung je Domain |

Umgebungsvariablen: `ACME_HELPER_CONFIG` (Default `/config/config.yaml`), `ACME_HELPER_DATA`
(Default `/data`), `ACME_HELPER_LOG_LEVEL` (`DEBUG` zeigt certbot-Aufrufe und HTTP-Details).

## Konfiguration

Siehe [config/config.example.yaml](config/config.example.yaml). Secrets stehen ausschließlich in `.env`;
die YAML referenziert nur die Variablennamen (`*_env`).

### DNS-Provider und Zonen

`zones` ordnet Zonen-Suffixe einem Provider zu. Gematcht wird gegen den **Zielnamen nach
CNAME-Auflösung**, der längste Suffix gewinnt. Dadurch funktioniert CNAME-Delegation ohne Sonderlogik:

```
_acme-challenge.meine-strato-domain.de.  CNAME  _acme-challenge.meine-strato-domain.de.acme.example.net.
```

Der CNAME wird einmalig bei Strato gesetzt. Danach schreibt der Container die TXT-Records nur noch bei
Cloudflare oder do.de (Zone `acme.example.net` in `zones` eintragen). Strato-Zugangsdaten sind dann nicht
nötig.

| Provider | Zugang | Hinweise | Anleitung |
|---|---|---|---|
| `cloudflare` | API-Token mit `Zone:DNS:Edit` und `Zone:Zone:Read` | Zone wird automatisch über den Namen gefunden | [docs/providers/cloudflare.md](docs/providers/cloudflare.md) |
| `dode` | Let's-Encrypt-Token aus my.do.de | API kann Werte nicht einzeln löschen; Cleanup entfernt alle TXT unter dem Namen (erst nach der Validierung) | [docs/providers/dode.md](docs/providers/dode.md) |
| `strato` | Kundennummer/Passwort, optional TOTP-Secret + Gerätename | Automatisiert den Kundenlogin. Bricht bei UI-Änderungen; das HTML landet dann unter `/data/debug` | [docs/providers/strato.md](docs/providers/strato.md) |

Jede Anleitung beschreibt Schritt für Schritt, wo im jeweiligen Kundenportal Token bzw. Zugangsdaten erzeugt
werden, wie der Eintrag in acme-helper aussieht, wie man ihn mit `dns-test` prüft und welche Fehlermeldungen
welche Ursache haben. Die Strato-Anleitung enthält die komplette CNAME-Delegation.

### FortiWeb

Ausführlich in [docs/providers/fortiweb.md](docs/providers/fortiweb.md): Admin-Account mit Access Profile und
Trusted Host, Admin-Port, TLS-Prüfung mit eigenem CA-Bundle, welche Objekte gebunden werden, Firmware-Abweichungen
und Fehlerbilder.

Voraussetzungen auf der FortiWeb:

- Admin-Account mit REST-API-Zugriff und passendem Trusted Host (IP des Containers/Hosts).
- HTTPS-Admin-Port (Standard 8443, sonst `port` anpassen).
- Bei `verify_tls: false` wird das FortiWeb-Zertifikat nicht geprüft. Besser: CA-Bundle unter
  `/config/` ablegen und den Pfad eintragen.

Ablauf pro `deploy`-Ziel:

1. Upload als `<cert_name_prefix>-<YYYYMMDD>` (bei Kollision `-2`, `-3`, ...).
2. `chain_mode`:
   - `intermediate-group` (Default): Intermediates aus `chain.pem` werden als `le-<fingerprint>` hochgeladen,
     in die Gruppe `<prefix>-chain` (oder `intermediate_group`) aufgenommen, und die Gruppe wird in Policy/SNI gesetzt.
   - `fullchain`: `fullchain.pem` wird als Zertifikat hochgeladen (sofern die Firmware das akzeptiert).
   - `none`: nur das Leaf.
3. `server_policies`: Feld `certificate` (und `intermediate-certificate-group`) per GET-modify-PUT setzen.
   War `certificate-type: enable` (FortiWeb-eigenes ACME), wird es auf `disable` gestellt.
4. `sni`: Member der Gruppe, deren `domain` zu den Mustern passt, bekommen `local-cert` (und `inter-group`).
5. Verifikation per GET, danach werden alte `<prefix>-*`-Zertifikate bis auf `keep_old` gelöscht.

### FortiWeb-8.0.x: Punkte, die beim ersten Lauf zu prüfen sind

Die REST-Pfade stammen aus der Fortinet-Dokumentation (Community-Tip 342766, Ansible-Collection) und sind in
`fortiweb/client.py` unter `DEFAULT_ENDPOINTS` gesammelt. Weicht die Firmware ab, lassen sie sich je FortiWeb
über `endpoints:` überschreiben. `check --probe` ruft alle Listen-Endpunkte auf und zeigt, welche antworten.

| Schlüssel | Standardpfad |
|---|---|
| `local_cert` | `/api/v2.0/cmdb/system/certificate.local` (Liste, Löschen, Anlage per JSON bei `import_method: json`) |
| `local_cert_import` | `/api/v2.0/system/certificate.local.import_certificate` (multipart-Upload, Standard) |
| `inter_cert` | `/api/v2.0/cmdb/system/certificate.intermediate-certificate` (Liste, Löschen) |
| `inter_cert_import` | `/api/v2.0/system/certificate.intermediateca` (multipart `uploadedFile`, `type=localPC`; die FortiWeb vergibt den Namen selbst, z.B. `Inter_Cert_1`) |
| `inter_group` / `inter_group_members` | `/api/v2.0/cmdb/system/certificate.intermediate-certificate-group[/members]` (Member als Untertabelle: `?mkey=<gruppe>`, Löschen mit `&sub_mkey=<id>`) |
| `server_policy` | `/api/v2.0/cmdb/server-policy/policy` (PUT des ganzen Objekts ohne `*_val`-, `q_*`-, `can_*`-Felder) |
| `sni_group` / `sni_members` | `/api/v2.0/cmdb/system/certificate.sni[/members]` (Member als Untertabelle wie oben) |

Alle Pfade und Body-Formate wurden auf FortiWeb 8.0.7 gegen das Gerät geprüft (`scripts/fw_probe.py`). Die
offizielle Configuration-API-Referenz beschreibt Intermediates als JSON-Objekt mit PEM-Text und Member als Teil des
Objekts; beides lehnt die Firmware ab bzw. ignoriert es. Der Multipart-Upload und die Untertabellen sind der Weg,
den auch das GUI nutzt.

Weitere Stellschrauben: `body_wrapper` (`data` sendet `{"data": {...}}` bei PUT/POST, `none` das rohe Objekt) und
`import_method` (`multipart` ist der dokumentierte Weg, `json` nutzt `json_cert`).

## Betrieb

- **Daemon:** `docker compose up -d`. Lauf beim Start und täglich zu `schedule.time`. certbot erneuert erst
  30 Tage vor Ablauf, die übrigen Läufe sind Leerläufe.
- **Extern getriggert:** `docker compose run --rm acme-helper run --once` aus Host-Cron oder als Kubernetes CronJob.
- **Benachrichtigung:** `notify.webhook_url_env` sendet ein JSON mit `status`, `message`, `text` und `details`
  (kompatibel mit Slack/Teams-Incoming-Webhooks, ntfy und eigenen Endpunkten).
- **Daten:** Volume `/data` enthält `letsencrypt/` (certbot-Account, Lineages), `state/deployed.json`
  und `debug/` (Strato-HTML bei Fehlern). Regelmäßig sichern, sonst wird bei Verlust ein neuer Account angelegt.
- **Mehrere FortiWebs:** einfach mehrere Einträge unter `fortiwebs` und je Zertifikat mehrere `deploy`-Ziele.

## Entwicklung

```bash
python -m venv .venv && .venv/Scripts/activate      # Windows; unter Linux: source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

Die Tests laufen komplett offline (HTTP-Mocks über `responses`, Strato-HTML-Fixtures, In-Memory-FortiWeb).

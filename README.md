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

Fertiges Template: [unraid/acme-helper.xml](unraid/acme-helper.xml). Alle Einstellungen inklusive Secrets werden
als Variablen direkt in der Unraid-Oberfläche gesetzt, eine `config.yaml` ist nicht nötig.

Import, zwei Wege:

1. **Template-Datei ablegen:** XML nach `/boot/config/plugins/dockerMan/templates-user/acme-helper.xml` kopieren
   (z.B. per SMB über die `flash`-Freigabe), danach *Docker → Add Container → Template* auswählen.
2. **Template-Repository:** In *Apps → Settings → Template repositories* die URL
   `https://github.com/xozy22/fortiweb-acme-helper` eintragen, danach erscheint `acme-helper` unter Apps.

Das Image kommt aus der GitHub Container Registry: `ghcr.io/xozy22/fortiweb-acme-helper:latest`
(gebaut per GitHub Actions für amd64 und arm64). `PUID`/`PGID` stehen im Template auf 99/100 (nobody:users),
der Entrypoint setzt die Rechte auf `/data` entsprechend.

Nach dem Start in der Container-Konsole prüfen:

```bash
acme-helper check --probe
```

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

| Provider | Zugang | Hinweise |
|---|---|---|
| `cloudflare` | API-Token mit `Zone:DNS:Edit` und `Zone:Zone:Read` | Zone wird automatisch über den Namen gefunden |
| `dode` | Let's-Encrypt-Token aus my.do.de | API kann Werte nicht einzeln löschen; Cleanup entfernt alle TXT unter dem Namen (erst nach der Validierung) |
| `strato` | Kundennummer/Passwort, optional TOTP-Secret + Gerätename | Automatisiert den Kundenlogin. Bricht bei UI-Änderungen; das HTML landet dann unter `/data/debug` |

### FortiWeb

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
| `local_cert` | `/api/v2.0/system/certificate.local` |
| `local_cert_import` | `/api/v2.0/system/certificate.local.import_certificate` |
| `local_cert_json` | `/api/v2.0/system/certificate.local.json_cert` (bei `import_method: json`) |
| `inter_cert` / `inter_cert_import` | `/api/v2.0/system/certificate.intermediate_ca[.import_certificate]` |
| `inter_group` / `inter_group_members` | `/api/v2.0/cmdb/system/certificate.intermediate-certificate-group[/members]` |
| `server_policy` | `/api/v2.0/cmdb/server-policy/policy` |
| `sni_group` / `sni_members` | `/api/v2.0/cmdb/system/certificate.sni[/members]` |

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

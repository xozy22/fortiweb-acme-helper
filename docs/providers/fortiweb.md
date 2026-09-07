# FortiWeb vorbereiten

acme-helper spricht die REST-API der FortiWeb (Version 2.0, FortiWeb 7.x und 8.x) an. Dafür braucht es einen
Admin-Account, Netzwerkzugriff auf den Admin-Port und die Namen der Objekte, an die das Zertifikat gebunden wird.

## 1. Admin-Account anlegen

Einen eigenen Account statt `admin`, damit Rechte und Trusted Hosts eng gefasst werden können.

1. **System → Admin → Administrators → Create New**.
2. **Name** z.B. `acme-helper`, **Type** Local User, sicheres Passwort.
3. **Access Profile:** ein Profil mit Schreibrecht auf *Server Policy* und *System → Certificates*. Zum Einstieg
   `prof_admin`; später auf ein eigenes Profil unter **System → Admin → Access Profile** einschränken
   (Read-Write für `Server Policy Configuration` und `System Configuration`, alles andere None).
4. **Trusted Host:** die IP des Docker-/Unraid-Hosts, z.B. `192.168.10.20/32`. Ohne passenden Trusted Host
   antwortet die FortiWeb mit HTTP 403 oder bricht die Verbindung ab.
5. Bei mehreren VDOMs: den Account der richtigen VDOM zuordnen und `FW_VDOM` bzw. `vdom` in der Config setzen.

Die REST-API nutzt denselben Login wie die GUI. Ein separater API-Key ist nicht nötig; acme-helper sendet
`Authorization: base64({"username","password","vdom"})`.

## 2. Netzwerk

- Admin-Port: **System → Admin → Settings → HTTPS Port** (Standard 443 oder 8443, je nach Installation).
  Diesen Wert als `FW_PORT` bzw. `port` eintragen.
- Auf dem Management-Interface muss HTTPS als **Administrative Access** erlaubt sein
  (**System → Network → Interface**).
- Firewall zwischen Docker-Host und Management-VLAN freischalten.

Test aus der Container-Konsole:

```bash
acme-helper diag
```

Zeigt DNS, TCP, TLS-Zertifikat der FortiWeb, ob die Zertifikatsprüfung mit `verify_tls` durchgeht und ob der
API-Login klappt.

## 3. TLS-Prüfung

Die FortiWeb-GUI hat werkseitig ein selbstsigniertes Zertifikat. Optionen:

- `FW_VERIFY_TLS=false` (Unraid) bzw. `verify_tls: false`: keine Prüfung. Einfach, aber anfällig für
  Man-in-the-Middle im Management-Netz.
- Besser: das GUI-Zertifikat der FortiWeb oder dessen CA als PEM unter `/config/fortiweb-ca.pem` ablegen
  (Unraid: `/mnt/user/appdata/acme-helper/config/`) und `FW_VERIFY_TLS=/config/fortiweb-ca.pem` setzen.
  Das Zertifikat lässt sich aus der Konsole holen:

  ```bash
  openssl s_client -connect 10.0.0.5:8443 -showcerts </dev/null 2>/dev/null \
    | sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' > /config/fortiweb-ca.pem
  ```

## 4. Objekte, an die gebunden wird

acme-helper ändert bestehende Objekte, es legt keine Server Policies oder SNI-Gruppen an.

**Server Policy** (**Policy → Server Policy**): Der Name der Policy kommt in `CERT1_POLICIES` bzw.
`server_policies`. acme-helper setzt dort das Feld *Certificate* (und *Intermediate CA Group*). War die Policy
auf ein FortiWeb-eigenes Let's-Encrypt-Zertifikat eingestellt (*Certificate Type = Let's Encrypt*), wird das auf
*Local* umgestellt.

**SNI-Gruppe** (**Server Objects → Certificates → SNI**): Für mehrere Domains auf einer Policy. Der Gruppenname
und optional die Domain-Muster der betroffenen Member kommen in `CERT1_SNI` (`gruppe:muster|muster`) bzw. `sni`.
acme-helper setzt bei den passenden Membern *Local Certificate* und *Intermediate CA Group*.

**Intermediate CA Group** (**Server Objects → Certificates → Intermediate CA**): Wird bei `chain_mode:
intermediate-group` (Standard) automatisch angelegt und mit den Let's-Encrypt-Intermediates befüllt, Name
`<prefix>-chain`. Muss nicht vorbereitet werden.

Ob die Namen stimmen, prüft:

```bash
acme-helper check
```

## 5. Ablauf eines Deploys

1. Upload als `<prefix>-<YYYYMMDD>` unter **Server Objects → Certificates → Local**.
2. Intermediates hochladen und in die Gruppe aufnehmen (idempotent, Name `le-<fingerprint>`).
3. Policy/SNI per GET lesen, Felder ändern, komplett per PUT zurückschreiben.
4. Verifikation per GET.
5. Alte `<prefix>-*`-Zertifikate löschen, `keep_old` (Standard 1) bleiben stehen.

Ein Zertifikat, das noch irgendwo referenziert ist, lehnt die FortiWeb beim Löschen ab. acme-helper protokolliert
das als Warnung und macht weiter.

## 6. Firmware-Abweichungen

Die REST-Pfade sind in `src/acme_helper/fortiweb/client.py` (`DEFAULT_ENDPOINTS`) gesammelt und stammen aus der
Fortinet-Dokumentation (Community Technical Tip 342766, Ansible-Collection). Zwei Punkte sind nicht für jede
Firmware belegt:

| Punkt | Standard | Alternative |
|---|---|---|
| Intermediate-CA-Liste und -Upload | wird beim ersten Zugriff automatisch ermittelt (mehrere Kandidaten, z.B. `certificate.intermediate_ca`, `certificate.intermediate-certificate`) | Meldet `check --probe` „kein Pfad gefunden“: im FortiWeb-GUI unter *Server Objects → Certificates → Intermediate CA* die Browser-Entwicklertools (F12, Reiter Netzwerk) öffnen, die Seite neu laden und den Pfad des Requests `/api/v2.0/...` unter `endpoints.inter_cert` eintragen. Oder `chain_mode: fullchain` (Unraid: `CERT1_CHAIN_MODE=fullchain`) |
| Body bei cmdb-PUT | `{"data": {...}}` | `FW_BODY_WRAPPER=none` bzw. `body_wrapper: none` |

`acme-helper check --probe` ruft alle Listen-Endpunkte auf und zeigt, welche antworten. Meldet ein Endpunkt 404,
im FortiWeb-API-Browser (`https://<fortiweb>:<port>/api/v2.0/...` im Browser mit GUI-Login) den korrekten Pfad
suchen und in der YAML-Config unter `fortiwebs.<name>.endpoints` eintragen.

## Fehlerbilder

| Meldung | Ursache |
|---|---|
| `nicht erreichbar ... Connection timed out` | Falscher Port, Firewall, oder bridge-Netz erreicht das Management-VLAN nicht (Unraid: `br0` verwenden) |
| `HTTP 403` | Trusted Host fehlt, oder Access Profile ohne Schreibrecht |
| `HTTP 401` | Benutzer/Passwort falsch, oder falsche VDOM |
| `Server Policy '...' existiert nicht` | Name in der Config stimmt nicht mit der FortiWeb überein (Groß-/Kleinschreibung) |
| `Verifikation fehlgeschlagen` | PUT wurde akzeptiert, aber das Feld hat sich nicht geändert; `body_wrapper` umstellen und Log auf DEBUG |
| `Zertifikat ... nach Upload nicht in der Liste gefunden` | FortiWeb hat den Namen anders gebildet; Log zeigt die Antwort, ggf. `import_method: json` testen |

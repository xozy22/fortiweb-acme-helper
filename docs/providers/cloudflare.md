# Cloudflare einrichten

Cloudflare ist der unkomplizierteste Provider: Ein API-Token mit DNS-Schreibrecht auf die betroffenen Zonen
genügt. Cloudflare erlaubt beliebig viele TXT-Werte unter demselben Namen, die Änderungen sind innerhalb weniger
Sekunden auf den autoritativen Nameservern sichtbar.

## Voraussetzungen

- Die Zone (z.B. `example.com`) liegt bei Cloudflare, d.h. die Nameserver der Domain zeigen auf
  `*.ns.cloudflare.com`. Das gilt auch, wenn die Domain woanders registriert ist und nur die DNS-Verwaltung bei
  Cloudflare läuft.
- Ein Cloudflare-Account mit Zugriff auf diese Zone.

## 1. API-Token erstellen

1. Im Dashboard oben rechts auf das Profil-Symbol → **My Profile** → Reiter **API Tokens**
   (direkt: <https://dash.cloudflare.com/profile/api-tokens>).
2. **Create Token** → beim Template **Edit zone DNS** auf **Use template** klicken.
3. Das Template setzt bereits `Zone / DNS / Edit`. Unter **Permissions** zusätzlich eine Zeile
   `Zone / Zone / Read` hinzufügen. Damit kann acme-helper die Zone anhand des Domainnamens finden.
4. Unter **Zone Resources** `Include / Specific zone / example.com` wählen. Mehrere Zonen: weitere Zeilen
   hinzufügen oder `All zones from an account`, wenn alle Zonen des Accounts erlaubt sein sollen.
5. Optional unter **Client IP Address Filtering** die öffentliche IP des Unraid-/Docker-Hosts eintragen.
   Dann ist das Token von anderen Adressen aus wertlos.
6. **Continue to summary** → **Create Token**. Das Token wird **nur einmal** angezeigt. Sofort kopieren.

Das Token ist ein etwa 40 Zeichen langer String. Es ist **kein** Global API Key und braucht keine E-Mail-Adresse.

## 2. Token prüfen

```bash
curl -s https://api.cloudflare.com/client/v4/user/tokens/verify \
  -H "Authorization: Bearer DEIN_TOKEN" | python3 -m json.tool
```

Erwartet wird `"status": "active"`. Das lässt sich auch aus der Container-Konsole ausführen.

## 3. In acme-helper eintragen

**Unraid / Env-Modus:** Variable `CF_API_TOKEN` setzen. Bei nur einem Provider ist `ZONES` optional, sonst
`ZONES=example.com=cf`.

**YAML-Modus:** In `.env` die Zeile `CF_API_TOKEN=...`, in `config.yaml`:

```yaml
dns_providers:
  cf:
    type: cloudflare
    api_token_env: CF_API_TOKEN
zones:
  - { suffix: example.com, provider: cf }
```

Der Suffix in `zones` muss nicht exakt die Cloudflare-Zone sein. `sub.example.com` als Suffix funktioniert
ebenfalls, acme-helper sucht die passende Zone von unten nach oben.

## 4. Testen

```bash
acme-helper check              # zeigt "Zone example.com erreichbar"
acme-helper dns-test example.com
```

`dns-test` setzt einen Test-TXT unter `_acme-challenge.example.com`, wartet, bis er auf den Cloudflare-Nameservern
sichtbar ist, und löscht ihn wieder.

## Cloudflare als Delegationsziel für andere Provider

Cloudflare eignet sich gut, um die Challenges von Strato-Domains aufzunehmen. Dafür in der Cloudflare-Zone keine
Vorbereitung nötig: acme-helper legt die TXT-Records unter dem CNAME-Ziel (z.B.
`_acme-challenge.strato-domain.de.acme.example.com`) selbst an. Nur `zones` muss das Ziel abdecken, hier reicht
der Eintrag `example.com=cf`. Die CNAME-Seite ist in der [Strato-Anleitung](strato.md) beschrieben.

## Fehlerbilder

| Meldung | Ursache |
|---|---|
| `6003: Invalid request headers` | Token falsch oder leer |
| `keine Zone für ... gefunden` | Token hat kein `Zone:Zone:Read` oder die Zone ist nicht in den Zone Resources |
| `9109: ... not authorized` | Token darf diese Zone nicht bearbeiten |
| TXT wird gesetzt, LE-Validierung schlägt trotzdem fehl | Domain nutzt gar nicht die Cloudflare-Nameserver; mit `dig NS example.com` prüfen |

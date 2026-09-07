# do.de (Domain-Offensive) einrichten

Domain-Offensive bietet eine eigene, schlanke Let's-Encrypt-API: Ein Token, ein GET-Aufruf pro TXT-Record.
Sie steht auch Privatkunden zur Verfügung und gilt für alle Domains, die über die do.de-Nameserver laufen.

## Voraussetzungen

- Die Domain liegt bei do.de **und** nutzt die do.de-Nameserver. Domains mit externen Nameservern kann die API
  nicht bedienen.
- Zugang zum Kundenportal <https://my.do.de>.

## 1. Let's-Encrypt-Token erzeugen

1. Im Kundenportal anmelden.
2. **Domains** → **Einstellungen** → **Let's Encrypt API-Token**.
3. Token erzeugen bzw. anzeigen lassen und kopieren. Es gibt ein Token pro Kundenkonto, das für alle Domains
   des Kontos gilt.

Die do.de-Dokumentation dazu: <https://www.do.de/wiki/freie-ssl-tls-zertifikate-ueber-acme/>.

## 2. Token prüfen

Die API hat keinen Lese-Endpunkt. Prüfen geht nur, indem ein Record gesetzt wird:

```bash
curl -s "https://my.do.de/api/letsencrypt?token=DEIN_TOKEN&domain=_acme-challenge.example.de&value=test123"
curl -s "https://my.do.de/api/letsencrypt?token=DEIN_TOKEN&domain=_acme-challenge.example.de&action=delete"
```

Beide Antworten müssen `success` enthalten. Genau das macht `acme-helper dns-test example.de` automatisch und
prüft dazwischen die autoritativen Nameserver.

## 3. In acme-helper eintragen

**Unraid / Env-Modus:** Variable `DODE_TOKEN` setzen, bei mehreren Providern `ZONES=example.de=dode`.

**YAML-Modus:**

```yaml
dns_providers:
  dode:
    type: dode
    token_env: DODE_TOKEN
zones:
  - { suffix: example.de, provider: dode }
```

## Besonderheiten der API

- **Löschen entfernt alle Werte** unter dem Namen. Die API kann einzelne TXT-Werte nicht adressieren. Für
  Wildcard + Basisdomain (zwei Werte unter `_acme-challenge.example.de`) ist das unkritisch: acme-helper setzt
  beide, Let's Encrypt validiert, erst danach wird aufgeräumt.
- **Propagation** dauert typischerweise unter einer Minute. Der Standard-Timeout von 300 s reicht.
- **Subdomains:** `domain=_acme-challenge.sub.example.de` funktioniert, solange `example.de` bei do.de liegt.

## do.de als Delegationsziel

Eine do.de-Zone kann die Challenges anderer Domains aufnehmen (z.B. von Strato). Der CNAME auf der Strato-Seite
zeigt dann auf `_acme-challenge.strato-domain.de.acme.example.de`; in `zones` muss `acme.example.de=dode` oder
einfach `example.de=dode` stehen. Details in der [Strato-Anleitung](strato.md).

## Fehlerbilder

| Meldung | Ursache |
|---|---|
| `do.de-API meldete Fehler ... not successful` | Token falsch, oder die Domain läuft nicht über do.de-Nameserver |
| Record gesetzt, aber nicht sichtbar | Externe Nameserver bei der Domain; mit `dig NS example.de` prüfen, es müssen do.de-Server sein |
| `keine Zone in 'zones' passt` | `ZONES` fehlt oder deckt den Namen nach CNAME-Auflösung nicht ab |

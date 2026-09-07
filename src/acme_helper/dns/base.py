from __future__ import annotations

from typing import Protocol


class DnsProvider(Protocol):
    """Minimale Schnittstelle: einen TXT-Wert unter einem FQDN setzen/entfernen.

    Beide Operationen müssen tolerant sein: add_txt darf bestehende Werte unter
    demselben Namen nicht löschen (Wildcard + Basisdomain teilen sich den Namen),
    remove_txt darf nicht fehlschlagen, wenn der Wert schon weg ist.
    """

    name: str

    def add_txt(self, fqdn: str, value: str) -> None: ...

    def remove_txt(self, fqdn: str, value: str) -> None: ...

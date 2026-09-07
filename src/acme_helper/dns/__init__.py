"""DNS-Provider und Auswahl über die Zonen-Konfiguration."""

from __future__ import annotations

from ..config import CloudflareProvider, Config, DodeProvider, StratoProvider, ZoneConfig
from ..errors import ConfigError
from .base import DnsProvider


def build_provider(cfg: Config, name: str) -> DnsProvider:
    pcfg = cfg.dns_providers.get(name)
    if pcfg is None:
        raise ConfigError(f"DNS-Provider '{name}' ist nicht definiert")
    if isinstance(pcfg, CloudflareProvider):
        from .cloudflare import CloudflareDns

        return CloudflareDns(name, pcfg)
    if isinstance(pcfg, DodeProvider):
        from .dode import DodeDns

        return DodeDns(name, pcfg)
    if isinstance(pcfg, StratoProvider):
        from .strato import StratoDns

        return StratoDns(name, pcfg, debug_dir=cfg.debug_dir)
    raise ConfigError(f"Unbekannter Provider-Typ für '{name}'")


def match_zone(name: str, zones: list[ZoneConfig]) -> ZoneConfig | None:
    """Längster passender Suffix gewinnt."""
    name = name.rstrip(".").lower()
    best: ZoneConfig | None = None
    for z in zones:
        if name == z.suffix or name.endswith("." + z.suffix):
            if best is None or len(z.suffix) > len(best.suffix):
                best = z
    return best


def provider_for(cfg: Config, target_fqdn: str) -> tuple[ZoneConfig, DnsProvider]:
    zone = match_zone(target_fqdn, cfg.zones)
    if zone is None:
        raise ConfigError(
            f"Keine Zone in 'zones' passt zu '{target_fqdn}'. "
            "Bei CNAME-Delegation muss das Delegationsziel in 'zones' stehen."
        )
    return zone, build_provider(cfg, zone.provider)


def propagation_timeout_for(cfg: Config, provider_name: str) -> int:
    pcfg = cfg.dns_providers[provider_name]
    if isinstance(pcfg, StratoProvider):
        return max(pcfg.propagation_timeout, cfg.acme.propagation_timeout)
    return cfg.acme.propagation_timeout

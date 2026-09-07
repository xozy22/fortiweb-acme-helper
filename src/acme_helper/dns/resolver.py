"""CNAME-Verfolgung, Zonen-Ermittlung und Propagation-Check gegen autoritative Nameserver."""

from __future__ import annotations

import logging
import time

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rdatatype
import dns.resolver

from ..errors import DnsError

log = logging.getLogger(__name__)

MAX_CNAME_HOPS = 5
QUERY_TIMEOUT = 5.0


def _norm(name: str) -> str:
    return name.strip().rstrip(".").lower()


def challenge_name(domain: str) -> str:
    """'*.example.com' und 'example.com' -> '_acme-challenge.example.com'."""
    d = _norm(domain)
    if d.startswith("*."):
        d = d[2:]
    return f"_acme-challenge.{d}"


def follow_cname(fqdn: str, resolver: dns.resolver.Resolver | None = None) -> str:
    """Folgt CNAMEs (max. MAX_CNAME_HOPS) und liefert den Zielnamen, sonst den Namen selbst."""
    res = resolver or dns.resolver.Resolver()
    res.lifetime = QUERY_TIMEOUT * 2
    current = _norm(fqdn)
    for _ in range(MAX_CNAME_HOPS):
        try:
            answer = res.resolve(current, "CNAME", raise_on_no_answer=False)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            return current
        except dns.exception.DNSException as exc:
            log.warning("CNAME-Abfrage für %s fehlgeschlagen (%s), nutze Namen direkt", current, exc)
            return current
        rrset = answer.rrset
        if rrset is None or rrset.rdtype != dns.rdatatype.CNAME:
            return current
        target = _norm(rrset[0].target.to_text())
        log.info("CNAME: %s -> %s", current, target)
        current = target
    raise DnsError(f"Zu viele CNAME-Hops ab {fqdn}")


def find_zone_apex(fqdn: str, resolver: dns.resolver.Resolver | None = None) -> str:
    """Steigt labelweise auf, bis ein NS-RRset gefunden wird (= Zonen-Apex)."""
    res = resolver or dns.resolver.Resolver()
    res.lifetime = QUERY_TIMEOUT * 2
    name = dns.name.from_text(_norm(fqdn))
    while len(name.labels) > 1:
        try:
            answer = res.resolve(name, "NS", raise_on_no_answer=False)
            if answer.rrset is not None and answer.rrset.rdtype == dns.rdatatype.NS:
                return _norm(name.to_text())
        except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            pass
        except dns.exception.DNSException as exc:
            log.debug("NS-Abfrage %s: %s", name, exc)
        name = name.parent()
    raise DnsError(f"Kein Zonen-Apex für {fqdn} gefunden")


def authoritative_nameservers(zone: str, resolver: dns.resolver.Resolver | None = None) -> list[str]:
    """IP-Adressen der autoritativen Nameserver einer Zone."""
    res = resolver or dns.resolver.Resolver()
    res.lifetime = QUERY_TIMEOUT * 2
    try:
        ns_answer = res.resolve(zone, "NS")
    except dns.exception.DNSException as exc:
        raise DnsError(f"NS-Records für {zone} nicht auflösbar: {exc}") from exc
    ips: list[str] = []
    for rr in ns_answer:
        host = rr.target.to_text()
        for rtype in ("A", "AAAA"):
            try:
                for a in res.resolve(host, rtype):
                    ips.append(a.to_text())
            except dns.exception.DNSException:
                continue
    if not ips:
        raise DnsError(f"Keine Nameserver-Adressen für {zone}")
    return ips


def query_txt_direct(fqdn: str, server_ip: str) -> set[str] | None:
    """TXT-Werte direkt von einem Nameserver. None = Server nicht erreichbar."""
    q = dns.message.make_query(_norm(fqdn), dns.rdatatype.TXT)
    try:
        try:
            resp = dns.query.udp(q, server_ip, timeout=QUERY_TIMEOUT)
            if resp.flags & dns.flags.TC:
                resp = dns.query.tcp(q, server_ip, timeout=QUERY_TIMEOUT)
        except dns.exception.DNSException:
            resp = dns.query.tcp(q, server_ip, timeout=QUERY_TIMEOUT)
    except (dns.exception.DNSException, OSError):
        return None
    values: set[str] = set()
    for rrset in resp.answer:
        if rrset.rdtype != dns.rdatatype.TXT:
            continue
        for rr in rrset:
            values.add(b"".join(rr.strings).decode("utf-8", "replace"))
    return values


def wait_for_txt(
    records: list[tuple[str, str]],
    *,
    timeout: int,
    interval: int = 10,
    resolver: dns.resolver.Resolver | None = None,
) -> bool:
    """Wartet, bis jeder (fqdn, value) auf allen autoritativen NS seiner Zone sichtbar ist."""
    if not records:
        return True
    by_fqdn: dict[str, set[str]] = {}
    for fqdn, value in records:
        by_fqdn.setdefault(_norm(fqdn), set()).add(value)

    servers: dict[str, list[str]] = {}
    for fqdn in by_fqdn:
        zone = find_zone_apex(fqdn, resolver)
        servers[fqdn] = authoritative_nameservers(zone, resolver)
        log.info("Propagation-Check %s gegen %d NS der Zone %s", fqdn, len(servers[fqdn]), zone)

    deadline = time.monotonic() + timeout
    while True:
        missing: list[str] = []
        for fqdn, expected in by_fqdn.items():
            for ip in servers[fqdn]:
                seen = query_txt_direct(fqdn, ip)
                if seen is None:
                    log.debug("NS %s antwortet nicht für %s", ip, fqdn)
                    continue  # Nicht erreichbare NS blockieren nicht
                if not expected.issubset(seen):
                    missing.append(f"{fqdn}@{ip}")
        if not missing:
            log.info("Alle TXT-Records sichtbar")
            return True
        if time.monotonic() >= deadline:
            log.error("Timeout beim Propagation-Check, fehlend: %s", ", ".join(missing[:10]))
            return False
        log.info("Warte auf Propagation (%d offen) ...", len(missing))
        time.sleep(interval)


def txt_visible(fqdn: str, value: str, resolver: dns.resolver.Resolver | None = None) -> bool:
    """Einmalige Prüfung ohne Warten (für dns-test)."""
    zone = find_zone_apex(fqdn, resolver)
    for ip in authoritative_nameservers(zone, resolver):
        seen = query_txt_direct(fqdn, ip)
        if seen is not None and value in seen:
            return True
    return False

"""Pivot helpers for cross-module investigation."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from dragonflyX.modules.dns_tools import DNSResult
    from dragonflyX.modules.ip_intel.schemas import IPIntelResult


# Known two-part TLDs where the registrable domain is the last three labels.
_TWO_PART_TLDS: set[str] = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "sch.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "org.nz", "gov.nz",
    "co.jp", "ne.jp", "or.jp", "go.jp",
    "com.sg", "org.sg", "gov.sg",
    "com.vn", "net.vn", "org.vn", "edu.vn", "gov.vn",
    "com.hk", "org.hk", "gov.hk",
    "com.tw", "org.tw", "gov.tw",
    "co.kr", "or.kr", "go.kr",
    "co.in", "net.in", "org.in", "gov.in",
    "com.br", "org.br", "gov.br",
    "com.mx", "org.mx", "gov.mx",
}


def extract_hostname_from_ip_result(ip_result: IPIntelResult) -> str | None:
    """
    Extract the primary hostname from an IP intelligence result.

    Returns the first hostname found from ipinfo or Shodan hostnames.
    Returns None if no hostname available.
    """
    if ip_result.ipinfo and ip_result.ipinfo.hostname:
        return ip_result.ipinfo.hostname
    if ip_result.shodan and ip_result.shodan.hostnames:
        return ip_result.shodan.hostnames[0]
    return None


def extract_domain_from_hostname(hostname: str) -> str | None:
    """
    Extract the registrable domain from a hostname.

    Examples:
      mail.evil-domain.com → evil-domain.com
      evil-domain.com      → evil-domain.com
      localhost            → None

    Uses simple split on dots — take last two parts if TLD is simple,
    last three parts for known two-part TLDs.
    """
    hostname = hostname.strip().lower().rstrip(".")
    if not hostname or hostname == "localhost":
        return None

    parts = hostname.split(".")
    if len(parts) < 2:
        return None

    if len(parts) >= 3:
        potential_tld = ".".join(parts[-2:])
        if potential_tld in _TWO_PART_TLDS:
            return ".".join(parts[-3:])

    return ".".join(parts[-2:])


def extract_whois_emails(dns_result: DNSResult) -> list[str]:
    """
    Extract email addresses from WHOIS data in a DNS result.

    WHOIS data is a dict — look for keys: emails, email, registrant_email.
    Returns deduplicated list, empty list if none found.
    """
    import re

    whois_data = dns_result.whois or {}
    raw_emails: list[str] = []

    for key in ("emails", "email", "registrant_email", "registrar_email"):
        value = whois_data.get(key)
        if value is None:
            continue
        if isinstance(value, str):
            raw_emails.append(value)
        elif isinstance(value, list):
            raw_emails.extend(str(v) for v in value)

    seen: set[str] = set()
    deduped: list[str] = []
    email_pattern = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    for email in raw_emails:
        email_lower = email.lower().strip()
        if email_lower and email_lower not in seen and email_pattern.match(email_lower):
            seen.add(email_lower)
            deduped.append(email_lower)

    return deduped


def extract_ip_from_dns_result(dns_result: DNSResult) -> list[str]:
    """
    Extract IP addresses from A records in a DNS result.

    Returns dns_result.a — the list of IPv4 addresses.
    """
    return list(dns_result.a)

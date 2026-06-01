"""DNS lookup and WHOIS tools."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import dns.exception
import dns.resolver
import whois
from pydantic import BaseModel, Field

from dragonflyX.core.cache import cache
from dragonflyX.core.validators import validate_domain, validate_ip


class DNSRecord(BaseModel):
    """Single DNS record."""

    type: str
    value: str


class DNSResult(BaseModel):
    """DNS lookup result."""

    domain: str
    query_time: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    a: list[str] = Field(default_factory=list)
    aaaa: list[str] = Field(default_factory=list)
    mx: list[str] = Field(default_factory=list)
    ns: list[str] = Field(default_factory=list)
    txt: list[str] = Field(default_factory=list)
    cname: list[str] = Field(default_factory=list)
    soa: list[str] = Field(default_factory=list)
    txt_records: list[list[str]] = Field(default_factory=list)
    whois: dict[str, Any] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)
    cached: bool = False
    requested_types: list[str] = Field(default_factory=list)


def _parse_whois_date(value: Any) -> datetime | None:
    """
    Normalize WHOIS date values to datetime.

    Handles the inconsistent types returned by python-whois:
    - datetime objects: pass through
    - lists: take first element if non-empty
    - strings: return None (too many formats to parse safely)
    """
    if isinstance(value, list):
        return value[0] if value else None
    if isinstance(value, datetime):
        return value
    return None


async def lookup_domain(
    domain: str,
    record_types: list[str] | None = None,
    use_cache: bool = True,
) -> DNSResult:
    """
    Perform DNS lookup for a domain.

    Args:
        domain: Domain name to lookup
        record_types: List of record types to query (default: all)
        use_cache: Whether to use cached results

    Returns:
        DNSResult with all found records
    """
    validate_domain(domain)

    if use_cache:
        key = cache.make_key("dns", domain)
        cached = cache.get(key)
        if cached:
            result = DNSResult.model_validate(cached)
            result.cached = True
            return result

    if record_types is None:
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

    result = DNSResult(domain=domain, requested_types=record_types)
    errors: list[str] = []

    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            records = [str(rdata) for rdata in answers]
            if record_type == "MX":
                records.sort(key=lambda x: int(x.split()[0]) if x.split() else 0)
            setattr(result, record_type.lower(), records)
        except dns.resolver.NXDOMAIN:
            errors.append(f"{record_type}: Domain does not exist")
        except dns.resolver.NoAnswer:
            errors.append(f"{record_type}: No records found")
        except dns.exception.DNSException:
            errors.append(f"{record_type}: Query failed")
            continue

    # WHOIS lookup
    try:
        w = whois.whois(domain)
        if w and w.domain_name:
            whois_data: dict[str, Any] = {}
            for key, value in w.items():
                if value is None:
                    continue
                if isinstance(value, datetime):
                    whois_data[key] = value.isoformat()
                elif isinstance(value, (list, str, int, float, bool)):
                    whois_data[key] = value
                else:
                    whois_data[key] = str(value)
            result.whois = whois_data
    except Exception as e:
        if "no output" in str(e).lower() or "not found" in str(e).lower():
            errors.append("WHOIS: Domain not found in WHOIS database")
        else:
            errors.append(f"WHOIS: Lookup failed ({type(e).__name__})")

    result.errors = errors

    if use_cache:
        cache.set(
            cache.make_key("dns", domain),
            result.model_dump(mode="json"),
            "dns",
        )

    return result


async def reverse_lookup(ip: str) -> str | None:
    """
    Perform reverse DNS lookup for an IP address.

    Args:
        ip: IP address to lookup

    Returns:
        Hostname or None if not found
    """
    validate_ip(ip)

    try:
        import socket
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except socket.herror:
        return None
    except OSError:
        return None

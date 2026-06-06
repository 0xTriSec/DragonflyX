"""DNS lookup and WHOIS tools."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

import dns.exception
import dns.resolver
import whois
from pydantic import BaseModel, Field

from dragonflyX.core.cache import cache
from dragonflyX.core.logger import logger
from dragonflyX.core.validators import validate_domain, validate_ip

SUBDOMAIN_WORDLIST: tuple[str, ...] = (
    "www", "mail", "smtp", "pop", "imap", "ftp", "ssh", "vpn",
    "dev", "staging", "test", "api", "admin", "portal", "dashboard",
    "login", "app", "cdn", "static", "assets", "media", "images",
    "img", "video", "docs", "wiki", "blog", "shop", "store",
    "payment", "pay", "checkout", "support", "help", "status",
    "monitor", "analytics", "metrics", "grafana", "jenkins",
    "gitlab", "git", "svn", "jira", "confluence", "ldap", "auth",
    "sso", "oauth", "id", "accounts", "user", "users", "profile",
    "forum", "community", "chat", "mail2", "webmail", "mx",
    "ns1", "ns2", "ns3", "dns", "vpn2", "remote", "citrix", "rdp",
    "exchange", "autodiscover", "autoconfig", "cpanel", "whm",
    "plesk", "ftp2", "sftp", "backup", "db", "database", "mysql",
    "postgres", "redis", "elastic", "kibana", "splunk", "nagios",
    "zabbix", "prometheus", "vault", "consul", "k8s", "kubernetes",
    "docker", "registry", "nexus", "sonar", "qa", "uat", "prod",
    "production", "stage", "demo", "beta", "alpha", "old",
    "legacy", "archive", "internal",
)


class DNSRecord(BaseModel):
    """Single DNS record."""

    type: str
    value: str


class SubdomainResult(BaseModel):
    """Single subdomain enumeration result."""

    hostname: str
    ip_addresses: list[str] = Field(default_factory=list)
    is_wildcard: bool = False


class DNSResult(BaseModel):
    """DNS lookup result."""

    domain: str
    query_time: datetime = Field(default_factory=lambda: datetime.now(UTC))
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
    subdomains: list[SubdomainResult] = Field(default_factory=list)


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


async def _detect_wildcard(domain: str) -> str | None:
    """
    Detect wildcard DNS by resolving a random non-existent subdomain.

    Returns the wildcard IP if wildcard is active, None otherwise.
    A domain with wildcard DNS resolves every subdomain to the same IP,
    making brute-force results unreliable without filtering.
    """
    import secrets

    random_label = secrets.token_hex(12)
    test_hostname = f"{random_label}.{domain}"
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 3.0
        answers = resolver.resolve(test_hostname, "A")
        return str(answers[0])
    except Exception:
        return None


async def enumerate_subdomains(
    domain: str,
    concurrency: int = 20,
) -> list[SubdomainResult]:
    """
    Enumerate subdomains of a domain using a built-in wordlist.

    Resolves each candidate hostname concurrently using asyncio.
    Wildcard domains are detected first to avoid false positives.
    Results are sorted alphabetically by hostname.

    Args:
        domain: Base domain to enumerate (e.g. "example.com")
        concurrency: Maximum concurrent DNS resolutions

    Returns:
        List of SubdomainResult for each subdomain that resolved
    """
    wildcard_ip = await _detect_wildcard(domain)
    loop = asyncio.get_running_loop()
    semaphore = asyncio.Semaphore(concurrency)

    def _resolve_a_records(hostname: str) -> list[str]:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 3.0
        answers = resolver.resolve(hostname, "A")
        return [str(answer) for answer in answers]

    async def _check_subdomain(prefix: str) -> SubdomainResult | None:
        hostname = f"{prefix}.{domain}"
        async with semaphore:
            try:
                ip_addresses = await loop.run_in_executor(None, _resolve_a_records, hostname)
            except dns.exception.DNSException:
                return None
            except Exception:
                return None

        return SubdomainResult(
            hostname=hostname,
            ip_addresses=ip_addresses,
            is_wildcard=bool(wildcard_ip and wildcard_ip in ip_addresses),
        )

    tasks = [_check_subdomain(prefix) for prefix in SUBDOMAIN_WORDLIST]
    results = await asyncio.gather(*tasks)
    found = [result for result in results if result is not None]
    found.sort(key=lambda item: item.hostname)
    return found


async def lookup_domain(
    domain: str,
    use_cache: bool = True,
    enumerate_subs: bool = False,
) -> DNSResult:
    """
    Perform DNS lookup for a domain.

    Args:
        domain: Domain name to lookup
        use_cache: Whether to use cached results
        enumerate_subs: Whether to enumerate common subdomains

    Returns:
        DNSResult with all found records
    """
    validate_domain(domain)

    cache_source = "dns_subs" if enumerate_subs else "dns"

    if use_cache:
        key = cache.make_key(cache_source, domain)
        cached = cache.get(key)
        if cached:
            result = DNSResult.model_validate(cached)
            result.cached = True
            return result

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

    if enumerate_subs:
        result.subdomains = await enumerate_subdomains(domain)
        logger.debug(f"Found {len(result.subdomains)} subdomains for {domain}")

    result.errors = errors

    if use_cache:
        cache.set(
            cache.make_key(cache_source, domain),
            result.model_dump(mode="json"),
            cache_source,
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

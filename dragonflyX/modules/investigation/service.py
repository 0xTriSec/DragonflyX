"""Investigation service — orchestration and pivot logic."""

from __future__ import annotations

import time
from contextlib import contextmanager
from typing import TYPE_CHECKING

from dragonflyX.core.cache import cache
from dragonflyX.core.exceptions import InvalidInput
from dragonflyX.core.logger import logger
from dragonflyX.modules.dorks_generator import DorkResult, generate_dorks
from dragonflyX.modules.dns_tools import lookup_domain
from dragonflyX.modules.investigation.pivots import (
    extract_domain_from_hostname,
    extract_hostname_from_ip_result,
    extract_ip_from_dns_result,
    extract_whois_emails,
)
from dragonflyX.modules.ip_intel import analyze_ip
from dragonflyX.modules.paste_search import search_paste
from dragonflyX.modules.investigation.detect import detect_target
from dragonflyX.modules.investigation.schemas import (
    InvestigationResult,
    InvestigationStep,
)


@contextmanager
def _timed_step(result: InvestigationResult, name: str):
    """Context manager that records step timing and appends an InvestigationStep."""
    start = time.monotonic()
    try:
        yield
    except Exception as exc:
        duration_ms = int((time.monotonic() - start) * 1000)
        result.steps.append(
            InvestigationStep(
                name=name,
                status="failed",
                error=str(exc),
                duration_ms=duration_ms,
            )
        )
        raise
    else:
        duration_ms = int((time.monotonic() - start) * 1000)
        result.steps.append(
            InvestigationStep(
                name=name,
                status="completed",
                duration_ms=duration_ms,
            )
        )


async def investigate(
    target: str,
    use_cache: bool = True,
    enumerate_subs: bool = True,
) -> InvestigationResult:
    """
    Run a full OSINT investigation on a target.

    Accepts an IP address, domain name, or email address.
    Automatically detects the input type and runs the appropriate
    investigation flow, pivoting between data sources.

    Each step is independent — a failure in one step does not
    stop the investigation. Errors are collected in result.errors.

    Args:
        target: IP address, domain name, or email address
        use_cache: Use cached results where available
        enumerate_subs: Run subdomain enumeration (slower but more thorough)

    Returns:
        InvestigationResult with all findings

    Raises:
        InvalidInput: If target cannot be classified
    """
    detected = detect_target(target)

    if use_cache:
        cache_key = cache.make_key("investigation", target)
        cached = cache.get(cache_key)
        if cached:
            result = InvestigationResult.model_validate(cached)
            result.cached = True
            return result

    result = InvestigationResult(
        target=detected.normalized,
        target_type=detected.input_type,
    )

    try:
        if detected.input_type == "ip":
            await _investigate_ip(detected.normalized, result, use_cache, enumerate_subs)
        elif detected.input_type == "domain":
            await _investigate_domain(detected.normalized, result, use_cache, enumerate_subs)
        else:
            await _investigate_email(detected.normalized, result, use_cache, enumerate_subs)
    except InvalidInput:
        raise
    except Exception as exc:
        logger.warning(f"Investigation failed unexpectedly: {exc}")
        result.errors["investigation"] = str(exc)

    if use_cache:
        try:
            cache.set(
                cache.make_key("investigation", target),
                result.model_dump(mode="json"),
                "investigation",
            )
        except Exception as exc:
            logger.warning(f"Investigation cache write failed: {exc}")

    return result


async def _investigate_ip(
    ip: str,
    result: InvestigationResult,
    use_cache: bool,
    enumerate_subs: bool,
) -> None:
    """Run IP-first investigation flow."""
    # Step 1: IP intelligence
    try:
        with _timed_step(result, "IP intelligence"):
            ip_result = await analyze_ip(ip, use_cache=use_cache)

        result.ip_addresses = [ip_result.ip]
        result.ip_risk_level = ip_result.risk_level
        result.ip_risk_score = ip_result.risk_score
        if ip_result.ipinfo:
            result.ip_isp = ip_result.ipinfo.geo.org or ""
            result.ip_country = ip_result.ipinfo.geo.country or ""
        if ip_result.shodan:
            result.open_ports = list(ip_result.shodan.open_ports)

    except Exception as exc:
        logger.warning(f"Step IP intelligence failed: {exc}")
        result.errors["ip_intelligence"] = str(exc)
        return

    # Step 2: Pivot to domain via hostname
    try:
        hostname = extract_hostname_from_ip_result(ip_result)
        if hostname:
            domain = extract_domain_from_hostname(hostname)
            if domain:
                result.domains.append(domain)
                await _investigate_domain(domain, result, use_cache, enumerate_subs, prefix="pivot")
    except Exception as exc:
        logger.warning(f"DNS pivot failed: {exc}")
        result.errors["dns"] = str(exc)
        result.steps.append(InvestigationStep(
            name="DNS lookup",
            status="failed",
            error=str(exc),
        ))

    # Step 3: Paste search for IP
    try:
        with _timed_step(result, "Paste search (IP)"):
            pastes = await search_paste(ip, use_cache=use_cache)
            result.paste_hits += len(pastes)
            result.paste_sources.extend(p.paste_id for p in pastes)
    except Exception as exc:
        logger.warning(f"Step Paste search (IP) failed: {exc}")
        result.errors["paste_search_ip"] = str(exc)

    # Step 6: Dorks for primary domain if found
    if result.domains:
        try:
            with _timed_step(result, "Dorks generation"):
                dorks = await generate_dorks(result.domains[0])
                result.dork_urls.extend(d.url for d in dorks)
        except Exception as exc:
            logger.warning(f"Step Dorks generation failed: {exc}")
            result.errors["dorks"] = str(exc)


async def _investigate_domain(
    domain: str,
    result: InvestigationResult,
    use_cache: bool,
    enumerate_subs: bool,
    prefix: str = "main",
) -> None:
    """Run domain-first investigation flow."""
    step_prefix = f"{prefix} " if prefix else ""

    # Step 1: DNS + WHOIS
    try:
        with _timed_step(result, f"{step_prefix}DNS + WHOIS"):
            dns_result = await lookup_domain(
                domain, use_cache=use_cache, enumerate_subs=False
            )

        result.domains.append(domain)
        result.registrar = (dns_result.whois.get("registrar") or dns_result.whois.get("Registrar") or "")
        created = dns_result.whois.get("creation_date") or dns_result.whois.get("created")
        if isinstance(created, list):
            created = created[0] if created else ""
        result.domain_created = str(created) if created else ""
        result.whois_emails = extract_whois_emails(dns_result)
        result.nameservers = [
            str(ns) for ns in (dns_result.whois.get("name_servers") or dns_result.whois.get("nameservers") or [])
        ]

        # Pivot: IPs from A records
        ips = extract_ip_from_dns_result(dns_result)
        if ips:
            result.ip_addresses.extend(ips[:5])
            await _investigate_single_ip(ips[0], result, use_cache, enumerate_subs, prefix="pivot")

        # Pivot: WHOIS emails
        for email in result.whois_emails[:5]:
            try:
                with _timed_step(result, f"{step_prefix}Paste search (email)"):
                    pastes = await search_paste(email, use_cache=use_cache)
                    result.paste_hits += len(pastes)
                    result.paste_sources.extend(p.paste_id for p in pastes)
            except Exception as exc:
                logger.warning(f"Step Paste search (email {email}) failed: {exc}")
                result.errors[f"paste_search_email:{email}"] = str(exc)
    except Exception as exc:
        logger.warning(f"Step {step_prefix}DNS + WHOIS failed: {exc}")
        result.errors[f"{prefix}_dns".strip()] = str(exc)

    # Step 3: Subdomain enumeration
    if enumerate_subs:
        try:
            with _timed_step(result, f"{step_prefix}Subdomain enumeration"):
                dns_subs = await lookup_domain(
                    domain, use_cache=use_cache, enumerate_subs=True
                )
                result.subdomains = [s.hostname for s in dns_subs.subdomains]
        except Exception as exc:
            logger.warning(f"Step {step_prefix}Subdomain enumeration failed: {exc}")
            result.errors[f"{prefix}_subdomains".strip()] = str(exc)

    # Step 4: Paste search for domain
    try:
        with _timed_step(result, f"{step_prefix}Paste search (domain)"):
            pastes = await search_paste(domain, use_cache=use_cache)
            result.paste_hits += len(pastes)
            result.paste_sources.extend(p.paste_id for p in pastes)
    except Exception as exc:
        logger.warning(f"Step {step_prefix}Paste search (domain) failed: {exc}")
        result.errors[f"{prefix}_paste_domain".strip()] = str(exc)

    # Step 6: Dorks generation
    try:
        with _timed_step(result, f"{step_prefix}Dorks generation"):
            dorks = await generate_dorks(domain)
            result.dork_urls.extend(d.url for d in dorks)
    except Exception as exc:
        logger.warning(f"Step {step_prefix}Dorks generation failed: {exc}")
        result.errors[f"{prefix}_dorks".strip()] = str(exc)


async def _investigate_email(
    email: str,
    result: InvestigationResult,
    use_cache: bool,
    enumerate_subs: bool,
) -> None:
    """Run email-first investigation flow."""
    domain = email.split("@")[1] if "@" in email else ""

    # Step 1: Extract domain (no async needed)
    with _timed_step(result, "Extract domain from email"):
        if not domain:
            raise InvalidInput("email", email, "missing domain part after @")

    if domain:
        result.domains.append(domain)

    # Step 2: DNS + WHOIS for domain
    if domain:
        try:
            with _timed_step(result, "DNS + WHOIS"):
                dns_result = await lookup_domain(
                    domain, use_cache=use_cache, enumerate_subs=False
                )

            result.registrar = (
                dns_result.whois.get("registrar") or dns_result.whois.get("Registrar") or ""
            )
            created = dns_result.whois.get("creation_date") or dns_result.whois.get("created")
            if isinstance(created, list):
                created = created[0] if created else ""
            result.domain_created = str(created) if created else ""
            result.nameservers = [
                str(ns)
                for ns in (
                    dns_result.whois.get("name_servers") or dns_result.whois.get("nameservers") or []
                )
            ]

            ips = extract_ip_from_dns_result(dns_result)
            if ips:
                result.ip_addresses.extend(ips[:5])
                await _investigate_single_ip(ips[0], result, use_cache, enumerate_subs)
        except Exception as exc:
            logger.warning(f"Step DNS + WHOIS failed: {exc}")
            result.errors["dns_whois"] = str(exc)

        # Step 4: Subdomain enumeration
        if enumerate_subs:
            try:
                with _timed_step(result, "Subdomain enumeration"):
                    dns_subs = await lookup_domain(
                        domain, use_cache=use_cache, enumerate_subs=True
                    )
                    result.subdomains = [s.hostname for s in dns_subs.subdomains]
            except Exception as exc:
                logger.warning(f"Step Subdomain enumeration failed: {exc}")
                result.errors["subdomains"] = str(exc)

    # Step 5: Paste search for email
    try:
        with _timed_step(result, "Paste search (email)"):
            pastes = await search_paste(email, use_cache=use_cache)
            result.paste_hits += len(pastes)
            result.paste_sources.extend(p.paste_id for p in pastes)
    except Exception as exc:
        logger.warning(f"Step Paste search (email) failed: {exc}")
        result.errors["paste_search_email"] = str(exc)

    # Step 6: Paste search for domain
    if domain:
        try:
            with _timed_step(result, "Paste search (domain)"):
                pastes = await search_paste(domain, use_cache=use_cache)
                result.paste_hits += len(pastes)
                result.paste_sources.extend(p.paste_id for p in pastes)
        except Exception as exc:
            logger.warning(f"Step Paste search (domain) failed: {exc}")
            result.errors["paste_search_domain"] = str(exc)

    # Step 7: Dorks generation
    try:
        with _timed_step(result, "Dorks generation"):
            dorks = await generate_dorks(email)
            result.dork_urls.extend(d.url for d in dorks)
    except Exception as exc:
        logger.warning(f"Step Dorks generation failed: {exc}")
        result.errors["dorks"] = str(exc)


async def _investigate_single_ip(
    ip: str,
    result: InvestigationResult,
    use_cache: bool,
    enumerate_subs: bool,
    prefix: str = "pivot",
) -> None:
    """Run IP intelligence for a single IP and pivot if hostname found."""
    try:
        with _timed_step(result, f"{prefix} IP intelligence"):
            ip_result = await analyze_ip(ip, use_cache=use_cache)

        if result.ip_addresses == [ip] or ip in result.ip_addresses:
            result.ip_risk_level = ip_result.risk_level
            result.ip_risk_score = ip_result.risk_score
            if ip_result.ipinfo:
                result.ip_isp = ip_result.ipinfo.geo.org or result.ip_isp
                result.ip_country = ip_result.ipinfo.geo.country or result.ip_country
            if ip_result.shodan:
                result.open_ports = list(ip_result.shodan.open_ports)

        hostname = extract_hostname_from_ip_result(ip_result)
        if hostname:
            domain = extract_domain_from_hostname(hostname)
            if domain and domain not in result.domains:
                result.domains.append(domain)
                await _investigate_domain(
                    domain, result, use_cache, enumerate_subs, prefix="pivot"
                )
    except Exception as exc:
        logger.warning(f"Step {prefix} IP intelligence failed: {exc}")
        result.errors[f"{prefix}_ip_intel".strip()] = str(exc)

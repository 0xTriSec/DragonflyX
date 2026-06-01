"""IP intelligence service - orchestrates all providers."""

from __future__ import annotations

import asyncio

from dragonflyX.core.cache import cache
from dragonflyX.core.exceptions import APIError, APIKeyMissing, NetworkError, RateLimited
from dragonflyX.core.http_client import get_client
from dragonflyX.core.validators import validate_ip
from dragonflyX.modules.ip_intel.providers import virustotal
from dragonflyX.modules.ip_intel.providers import abuseipdb
from dragonflyX.modules.ip_intel.providers import shodan
from dragonflyX.modules.ip_intel.providers import ipinfo
from dragonflyX.modules.ip_intel.schemas import IPIntelResult, RiskLevel


async def analyze_ip(ip: str, use_cache: bool = True) -> IPIntelResult:
    """
    Analyze an IP address using multiple threat intelligence providers.

    Args:
        ip: IP address to analyze
        use_cache: Whether to use cached results

    Returns:
        IPIntelResult with combined data from all providers
    """
    ip = validate_ip(ip)

    if use_cache:
        composite_key = cache.make_key("ip_intel", ip)
        cached = cache.get(composite_key)
        if cached:
            result = IPIntelResult.model_validate(cached)
            result.cached = True
            return result

    client = get_client()
    errors: dict[str, str] = {}

    vt_result = ab_result = sh_result = ip_result = None
    vt_task = ab_task = sh_task = ip_task = None

    try:
        async with asyncio.TaskGroup() as tg:
            vt_task = tg.create_task(virustotal.fetch(ip, client))
            ab_task = tg.create_task(abuseipdb.fetch(ip, client))
            sh_task = tg.create_task(shodan.fetch(ip, client))
            ip_task = tg.create_task(ipinfo.fetch(ip, client))
    except* (APIError, NetworkError, RateLimited, APIKeyMissing, asyncio.CancelledError) as eg:
        for exc in eg.exceptions:
            api_name = getattr(exc, "api_name", type(exc).__name__.lower())
            errors[api_name] = str(exc)

    def safe_result(task):
        if not task.done():
            return None
        try:
            return task.result()
        except (Exception, asyncio.CancelledError, KeyboardInterrupt):
            return None

    vt_result = safe_result(vt_task)
    ab_result = safe_result(ab_task)
    sh_result = safe_result(sh_task)
    ip_result = safe_result(ip_task)

    score = 0
    if vt_result:
        if vt_result.malicious > 5:
            score += 40
        elif vt_result.malicious >= 1:
            score += 20

    if ab_result:
        if ab_result.abuse_score > 80:
            score += 35
        elif ab_result.abuse_score >= 50:
            score += 20
        elif ab_result.abuse_score > 0:
            score += 5  # Baseline for any reports
        if ab_result.is_tor:
            score += 10

    if sh_result and sh_result.vulns:
        score += 15

    # Determine risk level based on score and available results
    if vt_result or ab_result or sh_result or ip_result:
        # We have results - classify by score
        if score >= 80:
            risk: RiskLevel = "critical"
        elif score >= 60:
            risk = "high"
        elif score >= 30:
            risk = "medium"
        else:
            risk = "low"  # 1-29 = low
    else:
        # No results available
        risk = "unknown"

    result = IPIntelResult(
        ip=ip,
        risk_level=risk,
        risk_score=min(score, 100),
        virustotal=vt_result,
        abuseipdb=ab_result,
        shodan=sh_result,
        ipinfo=ip_result,
        errors=errors,
    )

    if use_cache:
        cache.set(composite_key, result.model_dump(mode="json"), "ip_intel")

    return result

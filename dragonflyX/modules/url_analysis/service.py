"""URL analysis service - orchestrates all providers."""

from __future__ import annotations

import asyncio

from dragonflyX.core.cache import cache
from dragonflyX.core.exceptions import APIError, APIKeyMissing, NetworkError, RateLimited
from dragonflyX.core.http_client import get_client
from dragonflyX.core.validators import validate_url
from dragonflyX.modules.decoders import decode_url
from dragonflyX.modules.url_analysis.providers import urlscan as urlscan_provider
from dragonflyX.modules.url_analysis.providers import virustotal as vt_provider
from dragonflyX.modules.url_analysis.schemas import URLAnalysisResult, URLRiskLevel


async def analyze_url(url: str, use_cache: bool = True) -> URLAnalysisResult:
    """
    Analyze a URL using multiple scanning providers.

    Args:
        url: URL to analyze
        use_cache: Whether to use cached results

    Returns:
        URLAnalysisResult with combined data from all providers
    """
    decoded_url, encoding_type = decode_url(url)
    url_to_scan = decoded_url if decoded_url != url else url
    url_to_scan = validate_url(url_to_scan)

    if use_cache:
        composite_key = cache.make_key("url_analysis", url_to_scan)
        cached = cache.get(composite_key)
        if cached:
            result = URLAnalysisResult.model_validate(cached)
            result.cached = True
            return result

    client = get_client()
    errors: dict[str, str] = {}
    key_map = {
        "www.virustotal.com": "virustotal",
        "virustotal.com": "virustotal",
        "api.abuseipdb.com": "abuseipdb",
        "api.shodan.io": "shodan",
        "ipinfo.io": "ipinfo",
    }
    us_result = vt_result = None

    try:
        async with asyncio.TaskGroup() as tg:
            us_task = tg.create_task(urlscan_provider.fetch(url_to_scan, client))
            vt_task = tg.create_task(vt_provider.fetch(url_to_scan, client))
    except* (APIError, NetworkError, RateLimited, APIKeyMissing, asyncio.CancelledError) as eg:
        for exc in eg.exceptions:
            api_name = getattr(exc, "api_name", "unknown")
            api_name = key_map.get(api_name, api_name)
            errors[api_name] = str(exc)

    def safe_result(task):
        if not task.done():
            return None
        try:
            return task.result()
        except (Exception, asyncio.CancelledError, KeyboardInterrupt):
            return None

    us_result = safe_result(us_task)
    vt_result = safe_result(vt_task)

    # Risk scoring
    score = 0
    if us_result:
        if us_result.verdict_malicious:
            score += 50
        if us_result.verdict_score > 50:
            score += int(us_result.verdict_score * 0.4)

    if vt_result:
        if vt_result.malicious >= 5:
            score += 40
        elif vt_result.malicious >= 1:
            score += 20
        if vt_result.suspicious > 0:
            score += 10

    # Determine risk level based on score and available results
    if us_result or vt_result:
        # Check for suspicious indicators first
        has_suspicious = (vt_result and vt_result.suspicious > 0) or \
                        (us_result and us_result.verdict_score > 30)

        if score >= 70:
            risk: URLRiskLevel = "malicious"
        elif score >= 30 or has_suspicious:
            risk = "suspicious"
        else:
            risk = "clean"  # 0-29 = clean/low
    else:
        # No results available
        risk = "unknown"

    result = URLAnalysisResult(
        url=url,
        decoded_url=decoded_url if decoded_url != url else None,
        encoding_type=encoding_type,
        risk_level=risk,
        risk_score=min(score, 100),
        urlscan=us_result,
        virustotal=vt_result,
        errors=errors,
    )

    if use_cache:
        cache.set(composite_key, result.model_dump(mode="json"), "url_analysis")

    return result

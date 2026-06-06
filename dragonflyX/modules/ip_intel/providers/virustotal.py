"""VirusTotal provider for IP intelligence."""

from datetime import UTC, datetime

from dragonflyX.config import require_key
from dragonflyX.core.cache import cache
from dragonflyX.core.exceptions import APIError, APIKeyMissing, NetworkError, RateLimited
from dragonflyX.core.http_client import HTTPClient
from dragonflyX.core.logger import logger
from dragonflyX.core.rate_limiter import rate_limiter
from dragonflyX.modules.ip_intel.schemas import VirusTotalIPResult


async def fetch(target: str, client: HTTPClient) -> VirusTotalIPResult | None:
    """
    Fetch IP reputation from VirusTotal.

    Args:
        target: IP address to check
        client: HTTP client instance

    Returns:
        VirusTotalIPResult or None if not found
    """
    try:
        api_key = require_key("virustotal")
    except APIKeyMissing:
        raise

    cache_key = cache.make_key("virustotal", target)
    cached = cache.get(cache_key)
    if cached:
        logger.debug(f"VirusTotal cache hit for {target}")
        return VirusTotalIPResult.model_validate(cached)

    async with rate_limiter.acquire("virustotal"):
        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
            headers = {"x-apikey": api_key}
            data = await client.get(url, headers=headers)
        except RateLimited:
            raise
        except APIError as e:
            if e.status_code == 404:
                return None
            raise
        except NetworkError:
            raise

        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        last_date = attrs.get("last_analysis_date")
        last_analysis_date = None
        if last_date:
            last_analysis_date = datetime.fromtimestamp(last_date, tz=UTC)

        result = VirusTotalIPResult(
            malicious=stats.get("malicious", 0),
            suspicious=stats.get("suspicious", 0),
            harmless=stats.get("harmless", 0),
            undetected=stats.get("undetected", 0),
            total_engines=sum(stats.values()),
            last_analysis_date=last_analysis_date,
            reputation=attrs.get("reputation", 0),
        )

        cache.set(cache_key, result.model_dump(mode="json"), source="virustotal")
        return result

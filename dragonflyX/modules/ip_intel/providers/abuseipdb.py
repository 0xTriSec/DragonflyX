"""AbuseIPDB provider for IP intelligence."""

from datetime import datetime

from dragonflyX.config import require_key
from dragonflyX.core.cache import cache
from dragonflyX.core.exceptions import APIError, APIKeyMissing, NetworkError, RateLimited
from dragonflyX.core.http_client import HTTPClient
from dragonflyX.core.logger import logger
from dragonflyX.core.rate_limiter import rate_limiter
from dragonflyX.modules.ip_intel.schemas import AbuseIPDBResult


async def fetch(target: str, client: HTTPClient) -> AbuseIPDBResult | None:
    """
    Fetch IP abuse data from AbuseIPDB.

    Args:
        target: IP address to check
        client: HTTP client instance

    Returns:
        AbuseIPDBResult or None if private IP
    """
    try:
        api_key = require_key("abuseipdb")
    except APIKeyMissing:
        raise

    cache_key = cache.make_key("abuseipdb", target)
    cached = cache.get(cache_key)
    if cached:
        logger.debug(f"AbuseIPDB cache hit for {target}")
        return AbuseIPDBResult.model_validate(cached)

    async with rate_limiter.acquire("abuseipdb"):
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {
                "Key": api_key,
                "Accept": "application/json",
            }
            params = {
                "ipAddress": target,
                "maxAgeInDays": 90,
                "verbose": "true",
            }
            data = await client.get(url, headers=headers, params=params)
        except RateLimited:
            raise
        except APIError:
            raise
        except NetworkError:
            raise

        response_data = data.get("data", {})

        if not response_data.get("isPublic", True):
            return None

        last_reported_str = response_data.get("lastReportedAt")
        last_reported = None
        if last_reported_str:
            try:
                last_reported = datetime.fromisoformat(last_reported_str)
            except ValueError:
                pass

        result = AbuseIPDBResult(
            abuse_score=response_data.get("abuseConfidenceScore", 0),
            total_reports=response_data.get("totalReports", 0),
            last_reported=last_reported,
            isp=response_data.get("isp"),
            usage_type=response_data.get("usageType"),
            is_tor=response_data.get("isTor", False),
            country_code=response_data.get("countryCode"),
        )

        cache.set(cache_key, result.model_dump(mode="json"), source="abuseipdb")
        return result

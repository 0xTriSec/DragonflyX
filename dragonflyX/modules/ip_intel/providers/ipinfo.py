"""ipinfo.io provider for IP intelligence."""

from dragonflyX.core.cache import cache
from dragonflyX.core.exceptions import NetworkError
from dragonflyX.core.http_client import HTTPClient
from dragonflyX.core.logger import logger
from dragonflyX.modules.ip_intel.schemas import GeoInfo, IPInfoResult


async def fetch(target: str, client: HTTPClient) -> IPInfoResult | None:
    """
    Fetch IP geolocation data from ipinfo.io (no API key required).

    Args:
        target: IP address to check
        client: HTTP client instance

    Returns:
        IPInfoResult
    """
    cache_key = cache.make_key("ipinfo", target)
    cached = cache.get(cache_key)
    if cached:
        logger.debug(f"ipinfo cache hit for {target}")
        return IPInfoResult.model_validate(cached)

    try:
        url = f"https://ipinfo.io/{target}/json"
        data = await client.get(url)
    except NetworkError:
        raise

    if data.get("bogon"):
        result = IPInfoResult(is_bogon=True)
        cache.set(cache_key, result.model_dump(mode="json"), source="ipinfo")
        return result

    org = data.get("org")
    asn = None
    if org and org.startswith("AS"):
        asn = org.split()[0] if org.split() else None

    loc = data.get("loc", "")
    latitude = None
    longitude = None
    if loc:
        try:
            lat, lng = loc.split(",")
            latitude = float(lat)
            longitude = float(lng)
        except (ValueError, IndexError):
            pass

    result = IPInfoResult(
        geo=GeoInfo(
            country=data.get("country"),
            city=data.get("city"),
            org=org,
            asn=asn,
            latitude=latitude,
            longitude=longitude,
        ),
        hostname=data.get("hostname"),
        is_bogon=False,
    )

    cache.set(cache_key, result.model_dump(mode="json"), source="ipinfo")
    return result

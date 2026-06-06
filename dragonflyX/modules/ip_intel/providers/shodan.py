"""Shodan provider for IP intelligence."""

from dragonflyX.config import require_key
from dragonflyX.core.cache import cache
from dragonflyX.core.exceptions import APIError, APIKeyMissing, NetworkError, RateLimited
from dragonflyX.core.http_client import HTTPClient
from dragonflyX.core.logger import logger
from dragonflyX.core.rate_limiter import rate_limiter
from dragonflyX.modules.ip_intel.schemas import PortInfo, ShodanResult, VulnInfo


async def fetch(target: str, client: HTTPClient) -> ShodanResult:
    """
    Fetch IP data from Shodan.

    Args:
        target: IP address to check
        client: HTTP client instance

    Returns:
        ShodanResult (empty lists if not indexed)
    """
    try:
        api_key = require_key("shodan")
    except APIKeyMissing:
        raise

    cache_key = cache.make_key("shodan", target)
    cached = cache.get(cache_key)
    if cached:
        logger.debug(f"Shodan cache hit for {target}")
        return ShodanResult.model_validate(cached)

    async with rate_limiter.acquire("shodan"):
        try:
            url = f"https://api.shodan.io/shodan/host/{target}"
            params = {"key": api_key}
            data = await client.get(url, params=params)
        except RateLimited:
            raise
        except APIError as e:
            if e.status_code == 404:
                return ShodanResult()
            raise
        except NetworkError:
            raise

        ports = data.get("ports", [])
        services = []
        for item in data.get("data", []):
            services.append(
                PortInfo(
                    port=item.get("port", 0),
                    protocol=item.get("transport"),
                    service=item.get("product"),
                    banner=(item.get("banner", "") or "")[:200],
                )
            )

        vulns_raw = data.get("vulns", {})

        if isinstance(vulns_raw, dict):
            vulns = [
                VulnInfo(
                    cve_id=cve_id,
                    cvss=val.get("cvss") if isinstance(val, dict) else None,
                    summary=val.get("summary") if isinstance(val, dict) else None,
                )
                for cve_id, val in vulns_raw.items()
            ]
        elif isinstance(vulns_raw, list):
            vulns = [VulnInfo(cve_id=cve_id) for cve_id in vulns_raw if isinstance(cve_id, str)]
        else:
            vulns = []

        result = ShodanResult(
            open_ports=ports,
            services=services,
            vulns=vulns,
            hostnames=data.get("hostnames", []),
            tags=data.get("tags", []),
            last_update=data.get("last_update"),
            os=data.get("os"),
        )

        cache.set(cache_key, result.model_dump(mode="json"), source="shodan")
        return result

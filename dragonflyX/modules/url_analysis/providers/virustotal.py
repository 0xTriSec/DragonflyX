"""VirusTotal provider for URL analysis."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import httpx

from dragonflyX.config import require_key
from dragonflyX.core.cache import cache
from dragonflyX.core.exceptions import APIError, APIKeyMissing, NetworkError, RateLimited
from dragonflyX.core.http_client import HTTPClient
from dragonflyX.core.logger import logger
from dragonflyX.core.rate_limiter import rate_limiter
from dragonflyX.modules.url_analysis.schemas import VTURLResult


async def fetch(target: str, client: HTTPClient) -> VTURLResult | None:
    """
    Submit URL to VirusTotal and retrieve analysis results.

    Args:
        target: URL to analyze
        client: HTTP client instance

    Returns:
        VTURLResult or None on failure
    """
    try:
        api_key = require_key("virustotal")
    except APIKeyMissing:
        raise

    cache_key = cache.make_key("urlscan_vt", target)
    cached = cache.get(cache_key)
    if cached:
        logger.debug(f"VirusTotal URL cache hit for {target}")
        return VTURLResult.model_validate(cached)

    async with rate_limiter.acquire("virustotal"):
        submit_url = "https://www.virustotal.com/api/v3/urls"
        headers = {"x-apikey": api_key}
        submit_resp = None

        try:
            async with httpx.AsyncClient(timeout=30.0) as http_client:
                response = await http_client.post(
                    submit_url,
                    headers=headers,
                    data={"url": target},
                )
                if response.status_code in (200, 201):
                    submit_resp = response.json()
                elif response.status_code == 409:
                    # URL already submitted - ID is in the response
                    submit_resp = response.json()
                else:
                    error_data = response.json()
                    raise APIError(
                        api_name="virustotal",
                        status_code=response.status_code,
                        message=str(error_data),
                    )
        except (RateLimited, NetworkError, APIError):
            raise

        analysis_id = submit_resp.get("data", {}).get("id") if submit_resp else None
        if not analysis_id:
            return None

        # Poll for analysis completion
        poll_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        for attempt in range(6):
            await asyncio.sleep(10)
            try:
                async with httpx.AsyncClient(timeout=30.0) as http_client:
                    poll_response = await http_client.get(poll_url, headers=headers)
                    if poll_response.status_code == 404:
                        logger.debug(f"VT analysis still queued (attempt {attempt + 1}/6)")
                        continue
                    elif poll_response.status_code != 200:
                        raise APIError(
                            api_name="virustotal",
                            status_code=poll_response.status_code,
                            message=poll_response.text,
                        )
                    data = poll_response.json()
            except (RateLimited, NetworkError, APIError):
                raise

            attrs = data.get("attributes", {})
            if attrs.get("status") != "queued":
                stats = attrs.get("stats", {})

                last_date = attrs.get("date")
                last_analysis_date = None
                if last_date:
                    last_analysis_date = datetime.fromtimestamp(last_date, tz=UTC)

                result = VTURLResult(
                    malicious=stats.get("malicious", 0),
                    suspicious=stats.get("suspicious", 0),
                    harmless=stats.get("harmless", 0),
                    undetected=stats.get("undetected", 0),
                    total_engines=sum(stats.values()),
                    last_analysis_date=last_analysis_date,
                    final_url=data.get("meta", {}).get("url_info", {}).get("url"),
                )

                cache.set(cache_key, result.model_dump(mode="json"), source="urlscan_vt")
                return result

        logger.warning(f"VirusTotal URL analysis timeout for {target}")
        return None
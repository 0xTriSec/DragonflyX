"""URLScan.io provider for URL analysis."""

from __future__ import annotations

import asyncio
from datetime import datetime

import httpx

from dragonflyX.config import require_key
from dragonflyX.core.cache import cache
from dragonflyX.core.exceptions import APIError, APIKeyMissing, NetworkError, RateLimited
from dragonflyX.core.http_client import HTTPClient
from dragonflyX.core.logger import logger
from dragonflyX.core.rate_limiter import rate_limiter
from dragonflyX.modules.url_analysis.schemas import URLScanResult


async def fetch(target: str, client: HTTPClient) -> URLScanResult | None:
    """
    Submit URL to URLScan.io and retrieve results.

    Args:
        target: URL to scan
        client: HTTP client instance

    Returns:
        URLScanResult or None on failure
    """
    try:
        api_key = require_key("urlscan")
    except APIKeyMissing:
        raise

    cache_key = cache.make_key("urlscan", target)
    cached = cache.get(cache_key)
    if cached:
        logger.debug(f"URLScan cache hit for {target}")
        return URLScanResult.model_validate(cached)

    async with rate_limiter.acquire("urlscan"):
        submit_url = "https://urlscan.io/api/v1/scan/"
        headers = {
            "API-Key": api_key,
            "Content-Type": "application/json",
        }
        body = {"url": target, "visibility": "unlisted"}
        scan_id = None

        try:
            async with httpx.AsyncClient(timeout=30.0) as http_client:
                response = await http_client.post(submit_url, headers=headers, json=body)

                if response.status_code in (200, 201):
                    submit_resp = response.json()
                    scan_id = submit_resp.get("uuid")
                elif response.status_code in (409, 400):
                    try:
                        data = response.json()
                        scan_id = data.get("uuid")
                    except Exception:
                        scan_id = None
                else:
                    raise APIError(
                        api_name="urlscan.io",
                        status_code=response.status_code,
                        message=response.text,
                    )
        except (RateLimited, NetworkError, APIError):
            raise

        if not scan_id:
            return None

        # Poll for results using httpx directly to ensure API-Key header is sent
        result_url = f"https://urlscan.io/api/v1/result/{scan_id}/"
        poll_headers = {"API-Key": api_key}

        for attempt in range(6):
            await asyncio.sleep(5)
            try:
                async with httpx.AsyncClient(timeout=30.0) as http_client:
                    poll_response = await http_client.get(result_url, headers=poll_headers)

                    if poll_response.status_code == 404:
                        logger.debug(f"URLScan still processing (attempt {attempt + 1}/6)")
                        continue
                    elif poll_response.status_code != 200:
                        raise APIError(
                            api_name="urlscan.io",
                            status_code=poll_response.status_code,
                            message=poll_response.text,
                        )
                    data = poll_response.json()
            except (RateLimited, NetworkError, APIError):
                raise

            verdict_malicious = data.get("verdicts", {}).get("overall", {}).get("malicious", False)
            verdict_score = data.get("verdicts", {}).get("overall", {}).get("score", 0) or 0

            submit_time = None
            if task_time := data.get("task", {}).get("time"):
                try:
                    submit_time = datetime.fromisoformat(task_time)
                except ValueError:
                    pass

            result = URLScanResult(
                scan_id=scan_id,
                report_url=f"https://urlscan.io/result/{scan_id}/",
                screenshot_url=f"https://urlscan.io/screenshots/{scan_id}.png",
                verdict_malicious=verdict_malicious,
                verdict_score=verdict_score,
                ips_found=data.get("lists", {}).get("ips", [])[:20],
                domains_found=data.get("lists", {}).get("domains", [])[:20],
                submit_time=submit_time,
            )

            cache.set(cache_key, result.model_dump(mode="json"), source="urlscan")
            return result

        logger.warning(f"URLScan timeout for {target}, returning partial result")
        return URLScanResult(
            scan_id=scan_id,
            report_url=f"https://urlscan.io/result/{scan_id}/",
        )
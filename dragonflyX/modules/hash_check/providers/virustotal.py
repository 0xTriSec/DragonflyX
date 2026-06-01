"""VirusTotal provider for hash checking."""

from __future__ import annotations

from datetime import datetime, timezone

from dragonflyX.core.cache import cache
from dragonflyX.core.exceptions import APIError, APIKeyMissing, NetworkError, RateLimited
from dragonflyX.core.http_client import HTTPClient
from dragonflyX.core.logger import logger
from dragonflyX.core.rate_limiter import rate_limiter
from dragonflyX.config import require_key
from dragonflyX.modules.hash_check.schemas import EngineResult, HashCheckResult


async def fetch(target: str, hash_type: str, client: HTTPClient) -> HashCheckResult:
    """
    Fetch hash analysis from VirusTotal.

    Args:
        target: Hash value to check
        hash_type: Type of hash (md5, sha1, sha256, sha512)
        client: HTTP client instance

    Returns:
        HashCheckResult with analysis data
    """
    try:
        api_key = require_key("virustotal")
    except APIKeyMissing:
        raise

    cache_key = cache.make_key("hash_check", target)
    cached = cache.get(cache_key)
    if cached:
        logger.debug(f"VirusTotal hash cache hit for {target[:16]}...")
        return HashCheckResult.model_validate(cached)

    async with rate_limiter.acquire("virustotal"):
        try:
            url = f"https://www.virustotal.com/api/v3/files/{target}"
            headers = {"x-apikey": api_key}
            data = await client.get(url, headers=headers)
        except RateLimited:
            raise
        except NetworkError:
            raise
        except APIError as e:
            if e.status_code == 404:
                return HashCheckResult(
                    hash_value=target,
                    hash_type=hash_type,
                    risk_level="unknown",
                    risk_score=0,
                )
            raise

        attrs = data.get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total = malicious + suspicious + harmless + undetected

        # Parse top detections
        top_detections: list[EngineResult] = []
        analysis_results = attrs.get("last_analysis_results", {})
        for engine_name, detection in analysis_results.items():
            cat = detection.get("category", "")
            if cat in ("malicious", "suspicious"):
                top_detections.append(
                    EngineResult(
                        engine_name=engine_name,
                        category=cat,
                        result=detection.get("result"),
                    )
                )

        # Sort: malicious before suspicious
        top_detections.sort(key=lambda x: (0 if x.category == "malicious" else 1))
        top_detections = top_detections[:5]

        # Parse dates
        first_seen = None
        if attrs.get("first_submission_date"):
            first_seen = datetime.fromtimestamp(
                attrs["first_submission_date"], tz=timezone.utc
            )

        last_seen = None
        if attrs.get("last_analysis_date"):
            last_seen = datetime.fromtimestamp(
                attrs["last_analysis_date"], tz=timezone.utc
            )

        result = HashCheckResult(
            hash_value=target,
            hash_type=hash_type,
            file_type=attrs.get("type_description"),
            file_size=attrs.get("size"),
            meaningful_name=attrs.get("meaningful_name"),
            malicious_count=malicious,
            suspicious_count=suspicious,
            total_engines=total,
            detection_ratio=f"{malicious}/{total}" if total else "0/0",
            first_seen=first_seen,
            last_seen=last_seen,
            top_detections=top_detections,
            tags=attrs.get("tags", []),
        )

        cache.set(cache_key, result.model_dump(mode="json"), "hash_check")
        return result

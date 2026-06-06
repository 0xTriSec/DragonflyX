"""Hash check service - VirusTotal integration."""

from __future__ import annotations

from dragonflyX.core.cache import cache
from dragonflyX.core.http_client import get_client
from dragonflyX.core.validators import compute_file_hash, validate_hash
from dragonflyX.modules.hash_check.providers import virustotal
from dragonflyX.modules.hash_check.schemas import HashCheckResult


async def check_hash(hash_input: str, use_cache: bool = True) -> HashCheckResult:
    """
    Check a hash against VirusTotal.

    Args:
        hash_input: Hash value to check
        use_cache: Whether to use cached results

    Returns:
        HashCheckResult with analysis data
    """
    normalized, hash_type = validate_hash(hash_input)

    if use_cache:
        key = cache.make_key("hash_check", normalized)
        cached = cache.get(key)
        if cached:
            result = HashCheckResult.model_validate(cached)
            result.cached = True
            return result

    client = get_client()
    result = await virustotal.fetch(normalized, hash_type, client)

    # Risk scoring
    malicious = result.malicious_count

    if malicious >= 10:
        result.risk_level, result.risk_score = "critical", 90
    elif malicious >= 5:
        result.risk_level, result.risk_score = "high", 70
    elif malicious >= 1:
        result.risk_level, result.risk_score = "medium", 40
    elif result.malicious_count == 0 and result.suspicious_count == 0 and result.total_engines > 0:
        result.risk_level, result.risk_score = "low", 10
    else:
        result.risk_level, result.risk_score = "unknown", 0

    if use_cache:
        cache.set(
            cache.make_key("hash_check", normalized),
            result.model_dump(mode="json"),
            "hash_check",
        )

    return result


async def check_file(file_path: str, use_cache: bool = True) -> HashCheckResult:
    """
    Compute SHA256 hash of a file and check it against VirusTotal.

    Args:
        file_path: Path to the file
        use_cache: Whether to use cached results

    Returns:
        HashCheckResult with analysis data
    """
    sha256 = compute_file_hash(file_path)
    return await check_hash(sha256, use_cache=use_cache)

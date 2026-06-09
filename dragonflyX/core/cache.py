"""Disk-based caching with TTL support."""

from __future__ import annotations

from pathlib import Path

from diskcache import Cache

from dragonflyX.core.exceptions import CacheError
from dragonflyX.core.logger import logger

CACHE_DIR = Path.home() / ".dragonflyX" / ".cache"

TTL_MAP: dict[str, int] = {
    "virustotal":    6 * 3600,
    "abuseipdb":     3 * 3600,
    "shodan":       12 * 3600,
    "ipinfo":       24 * 3600,
    "urlscan":       1 * 3600,
    "urlscan_vt":    1 * 3600,
    "dns":          30 * 60,
    "dns_subs":     30 * 60,
    "phone_intel":  24 * 3600,
    "ip_intel":      1 * 3600,
    "url_analysis":  1 * 3600,
    "hash_check":    6 * 3600,
    "identity":      1 * 3600,
    "dorks":         7 * 24 * 3600,
    "leakcheck":    1 * 3600,
    "investigation": 30 * 60,
}
DEFAULT_TTL = 3600


class CacheManager:
    """Manages disk-based caching with TTL per source."""

    def __init__(self) -> None:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        self._cache = Cache(str(CACHE_DIR))

    def make_key(self, source: str, query: str) -> str:
        """
        Create a cache key.

        Args:
            source: API source name (e.g., 'virustotal')
            query: Query string (e.g., IP address)

        Returns:
            Cache key in format 'source:query'
        """
        return f"{source}:{query.lower().strip()}"

    def get(self, key: str) -> dict | None:
        """
        Get cached value by key.

        Args:
            key: Cache key

        Returns:
            Cached dict or None if not found
        """
        try:
            value = self._cache.get(key)
            if value is None:
                logger.debug(f"Cache miss: {key}")
                return None
            logger.debug(f"Cache hit: {key}")
            return value
        except Exception as e:
            raise CacheError(key=key, operation="get", reason=str(e)) from e

    def set(self, key: str, value: dict, source: str) -> None:
        """
        Set cache value with TTL based on source.

        Args:
            key: Cache key
            value: Data to cache
            source: API source for TTL lookup
        """
        ttl = TTL_MAP.get(source, DEFAULT_TTL)
        try:
            self._cache.set(key, value, expire=ttl)
        except Exception as e:
            raise CacheError(key=key, operation="set", reason=str(e)) from e

    def delete(self, key: str) -> None:
        """
        Delete a cache entry.

        Args:
            key: Cache key to delete
        """
        try:
            self._cache.delete(key)
        except Exception as e:
            raise CacheError(key=key, operation="delete", reason=str(e)) from e

    def clear_all(self) -> None:
        """Clear all cache entries."""
        self._cache.clear()

    def stats(self) -> dict:
        """
        Get cache statistics.

        Returns:
            Dict with size and directory info
        """
        return {
            "size": len(self._cache),
            "directory": str(CACHE_DIR),
        }


cache = CacheManager()

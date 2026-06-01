"""Rate limiting using semaphores and interval tracking."""

from __future__ import annotations

import asyncio
import time
from contextlib import asynccontextmanager

from dragonflyX.core.logger import logger

LIMITS: dict[str, dict] = {
    "virustotal": {"semaphore": 1, "min_interval": 15.0},
    "abuseipdb":  {"semaphore": 5, "min_interval": 0.0},
    "urlscan":    {"semaphore": 2, "min_interval": 0.0},
    "shodan":     {"semaphore": 1, "min_interval": 0.0},
    "ipinfo":     {"semaphore": 10, "min_interval": 0.0},
}


class RateLimiter:
    """
    Rate limiter using semaphores and minimum interval tracking.

    Semaphores are initialized lazily because asyncio.Semaphore
    requires an active event loop at construction time.
    """

    def __init__(self) -> None:
        self._semaphores: dict[str, asyncio.Semaphore] = {}
        self._last_call: dict[str, float] = {}

    def _get_semaphore(self, api_name: str) -> asyncio.Semaphore:
        """Get or create semaphore for API."""
        if api_name not in self._semaphores:
            count = LIMITS.get(api_name, {}).get("semaphore", 5)
            self._semaphores[api_name] = asyncio.Semaphore(count)
        return self._semaphores[api_name]

    @asynccontextmanager
    async def acquire(self, api_name: str):
        """
        Acquire rate limit slot for API.

        Args:
            api_name: Name of the API to rate limit

        Yields:
            Control to the caller while holding the slot
        """
        sem = self._get_semaphore(api_name)
        async with sem:
            min_interval = LIMITS.get(api_name, {}).get("min_interval", 0.0)
            if min_interval > 0.0:
                last = self._last_call.get(api_name, 0.0)
                wait = min_interval - (time.monotonic() - last)
                if wait > 0:
                    logger.debug(f"Rate limiter: sleeping {wait:.1f}s for {api_name}")
                    await asyncio.sleep(wait)
            yield
            self._last_call[api_name] = time.monotonic()


rate_limiter = RateLimiter()

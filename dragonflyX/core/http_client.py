"""HTTP client with retry logic and error handling."""

from __future__ import annotations

import asyncio
import random

import httpx

from dragonflyX.core.exceptions import APIError, NetworkError, RateLimited
from dragonflyX.core.logger import logger

_client_instance: HTTPClient | None = None


def get_client() -> HTTPClient:
    """Get or create singleton HTTPClient instance."""
    global _client_instance
    if _client_instance is None:
        _client_instance = HTTPClient()
    return _client_instance


class HTTPClient:
    """Async HTTP client with automatic retry and error handling."""

    DEFAULT_HEADERS = {
        "User-Agent": "DragonflyX/3.0.0 OSINT-SOC-Tool",
        "Accept": "application/json",
    }
    TIMEOUT = httpx.Timeout(10.0, connect=5.0)
    MAX_ATTEMPTS = 3

    def __init__(self) -> None:
        self._client: httpx.AsyncClient | None = None

    async def _ensure_client(self) -> httpx.AsyncClient:
        """Lazily initialize the httpx AsyncClient."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                headers=self.DEFAULT_HEADERS,
                timeout=self.TIMEOUT,
                follow_redirects=True,
            )
        return self._client

    def _extract_api_name(self, url: str) -> str:
        """Extract hostname from URL for error reporting."""
        try:
            return url.split("/")[2]
        except IndexError:
            return "unknown"

    async def get(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        params: dict | None = None,
    ) -> dict:
        """
        Perform GET request with retry logic.

        Args:
            url: Target URL
            headers: Optional HTTP headers
            params: Optional query parameters

        Returns:
            Parsed JSON response as dict

        Raises:
            RateLimited: When API returns 429
            APIError: When API returns 4xx/5xx
            NetworkError: When connection fails after retries
        """
        client = await self._ensure_client()
        api_name = self._extract_api_name(url)

        for attempt in range(1, self.MAX_ATTEMPTS + 1):
            try:
                logger.debug(f"GET {url} (attempt {attempt})")
                response = await client.get(url, headers=headers, params=params)

                if response.status_code == 429:
                    retry_after = int(response.headers.get("Retry-After", 60))
                    raise RateLimited(api_name=api_name, retry_after=retry_after)

                if response.status_code == 503:
                    if attempt < self.MAX_ATTEMPTS:
                        sleep_time = (2 ** attempt) + random.random()
                        logger.warning(f"HTTP 503 from {api_name}, retrying in {sleep_time:.1f}s")
                        await asyncio.sleep(sleep_time)
                        continue
                    raise APIError(api_name=api_name, status_code=503, message="Service unavailable")

                if 400 <= response.status_code < 500:
                    try:
                        body = response.json()
                        msg = str(body.get("error", body.get("message", response.text[:200])))
                    except Exception:
                        msg = response.text[:200]
                    raise APIError(api_name=api_name, status_code=response.status_code, message=msg)

                if response.status_code >= 500:
                    try:
                        body = response.json()
                        msg = str(body.get("error", body.get("message", response.text[:200])))
                    except Exception:
                        msg = response.text[:200]
                    raise APIError(api_name=api_name, status_code=response.status_code, message=msg)

                response.raise_for_status()

                try:
                    return response.json()
                except Exception:
                    raise APIError(
                        api_name=api_name,
                        status_code=response.status_code,
                        message=f"JSON decode failed: {response.text[:100]}",
                    )

            except (httpx.TimeoutException, httpx.ConnectError) as e:
                if attempt == self.MAX_ATTEMPTS:
                    raise NetworkError(url=url, reason=str(e))
                sleep_time = (2 ** attempt) + random.random()
                logger.warning(f"Network error on {url} (attempt {attempt}): {e}. Retrying in {sleep_time:.1f}s")
                await asyncio.sleep(sleep_time)

        raise NetworkError(url=url, reason="Max retries exceeded")

    async def post(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        json: dict | None = None,
        data: dict | None = None,
    ) -> dict:
        """
        Perform POST request with retry logic.

        Args:
            url: Target URL
            headers: Optional HTTP headers
            json: JSON body (mutually exclusive with data)
            data: Form-encoded body (mutually exclusive with json)

        Returns:
            Parsed JSON response as dict

        Raises:
            RateLimited: When API returns 429
            APIError: When API returns 4xx/5xx
            NetworkError: When connection fails after retries
        """
        client = await self._ensure_client()
        api_name = self._extract_api_name(url)

        for attempt in range(1, self.MAX_ATTEMPTS + 1):
            try:
                logger.debug(f"POST {url} (attempt {attempt})")
                response = await client.post(url, headers=headers, json=json, data=data)

                if response.status_code == 429:
                    retry_after = int(response.headers.get("Retry-After", 60))
                    raise RateLimited(api_name=api_name, retry_after=retry_after)

                if response.status_code == 503:
                    if attempt < self.MAX_ATTEMPTS:
                        sleep_time = (2 ** attempt) + random.random()
                        logger.warning(f"HTTP 503 from {api_name}, retrying in {sleep_time:.1f}s")
                        await asyncio.sleep(sleep_time)
                        continue
                    raise APIError(api_name=api_name, status_code=503, message="Service unavailable")

                if 400 <= response.status_code < 500:
                    try:
                        body = response.json()
                        msg = str(body.get("error", body.get("message", response.text[:200])))
                    except Exception:
                        msg = response.text[:200]
                    raise APIError(api_name=api_name, status_code=response.status_code, message=msg)

                response.raise_for_status()

                try:
                    return response.json()
                except Exception:
                    raise APIError(
                        api_name=api_name,
                        status_code=response.status_code,
                        message=f"JSON decode failed: {response.text[:100]}",
                    )

            except (httpx.TimeoutException, httpx.ConnectError) as e:
                if attempt == self.MAX_ATTEMPTS:
                    raise NetworkError(url=url, reason=str(e))
                sleep_time = (2 ** attempt) + random.random()
                logger.warning(f"Network error on {url} (attempt {attempt}): {e}. Retrying in {sleep_time:.1f}s")
                await asyncio.sleep(sleep_time)

        raise NetworkError(url=url, reason="Max retries exceeded")

    async def close(self) -> None:
        """Close the HTTP client connection."""
        if self._client is not None and not self._client.is_closed:
            await self._client.aclose()

    async def __aenter__(self) -> HTTPClient:
        """Async context manager entry."""
        await self._ensure_client()
        return self

    async def __aexit__(self, *args) -> None:
        """Async context manager exit."""
        await self.close()

"""Paste search via LeakCheck public API."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from urllib.parse import quote

import httpx

from dragonflyX.core.cache import cache
from dragonflyX.core.exceptions import APIError, NetworkError, RateLimited
from dragonflyX.core.logger import logger
from dragonflyX.core.rate_limiter import rate_limiter

# LeakCheck public API returns breach source metadata.
# The raw credential line is used only to compute the size field.
# Credential content is never logged, stored, or displayed.


@dataclass
class PasteResult:
    """Single paste search result."""

    paste_id: str
    url: str
    date: str
    size: int
    tags: list[str]

    def model_dump(self, *, mode: str = "json") -> dict:
        """Serialize to dict for report generation."""
        return asdict(self)


class PasteSearch:
    """Search LeakCheck for public breach entries mentioning a target."""

    BASE_URL = "https://leakcheck.io/api/public"
    CACHE_SOURCE = "leakcheck"
    REQUEST_TIMEOUT = httpx.Timeout(10.0)

    async def search(self, query: str, use_cache: bool = True) -> list[PasteResult]:
        """
        Search LeakCheck for breach entries matching the query.

        Args:
            query: Email address, username, domain, or IP address
            use_cache: Whether to use cached results

        Returns:
            List of PasteResult sorted by date descending
        """
        sanitized = self._sanitize_query(query)
        cache_key = cache.make_key(self.CACHE_SOURCE, sanitized)

        if use_cache:
            cached = cache.get(cache_key)
            if cached:
                logger.debug(f"leakcheck cache hit for '{sanitized}'")
                return [PasteResult(**item) for item in cached]

        results = await self._fetch(sanitized)
        results.sort(key=lambda result: result.date if result.date else "", reverse=True)

        if results:
            cache.set(
                cache_key,
                [result.model_dump(mode="json") for result in results],
                self.CACHE_SOURCE,
            )

        return results

    async def _fetch(self, query: str) -> list[PasteResult]:
        """
        Perform the API request with rate limiting and error handling.

        Args:
            query: Sanitized query string

        Returns:
            List of PasteResult, possibly empty on error
        """
        url = self._build_api_url(query)

        async with rate_limiter.acquire("leakcheck"):
            try:
                async with httpx.AsyncClient(timeout=self.REQUEST_TIMEOUT) as client:
                    response = await client.get(url)

                if response.status_code == 429:
                    logger.warning(f"leakcheck rate limited for '{query}'")
                    return []

                if 400 <= response.status_code:
                    message = self._extract_error_message(response)
                    raise APIError(
                        api_name="leakcheck.io",
                        status_code=response.status_code,
                        message=message,
                    )

                data = response.json()
                if not isinstance(data, dict):
                    logger.warning(
                        f"leakcheck returned unexpected type for '{query}': "
                        f"{type(data).__name__}"
                    )
                    return []

                if data.get("success") is False:
                    error_message = str(data.get("error", "Unknown error"))
                    logger.warning(
                        f"leakcheck returned an error for '{query}': {error_message}"
                    )
                    return []

                return self._parse_response(data, query)

            except RateLimited:
                logger.warning(f"leakcheck rate limited for '{query}'")
                return []
            except (httpx.TimeoutException, httpx.ConnectError) as error:
                logger.warning(f"leakcheck request failed for '{query}': {error}")
                return []
            except APIError as error:
                logger.warning(f"leakcheck request failed for '{query}': {error}")
                return []
            except NetworkError as error:
                logger.warning(f"leakcheck request failed for '{query}': {error}")
                return []
            except Exception as error:
                logger.warning(f"leakcheck request failed for '{query}': {error}")
                return []

    def _build_api_url(self, query: str) -> str:
        """Build the LeakCheck API URL for a sanitized query."""
        encoded_query = quote(query, safe="")
        return f"{self.BASE_URL}?check={encoded_query}"

    def _build_result_url(self, query: str) -> str:
        """Build the LeakCheck search URL for a query."""
        encoded_query = quote(query, safe="")
        return f"https://leakcheck.io/search?query={encoded_query}"

    def _extract_error_message(self, response: httpx.Response) -> str:
        """Extract a useful error message from an HTTP response."""
        try:
            data = response.json()
        except Exception:
            return response.text[:200]

        if isinstance(data, dict):
            return str(data.get("error", data.get("message", response.text[:200])))
        return response.text[:200]

    def _sanitize_query(self, query: str) -> str:
        """
        Strip characters that could form path traversal or injection sequences.

        Removes traversal dot sequences and slash separators while preserving
        single dots used in domains and email addresses.
        """
        sanitized = re.sub(r"\.{2,}", "", query)
        sanitized = sanitized.replace("/", "").replace("\\", "")
        return sanitized.strip()

    def _parse_response(self, data: dict, query: str) -> list[PasteResult]:
        """
        Parse raw API response into PasteResult objects.

        Args:
            data: Raw dict from API response
            query: Sanitized query string

        Returns:
            List of PasteResult, skipping malformed entries
        """
        results: list[PasteResult] = []
        raw_results = data.get("result", [])

        if not isinstance(raw_results, list):
            logger.warning(
                f"leakcheck returned invalid result field for '{query}': "
                f"{type(raw_results).__name__}"
            )
            return []

        result_url = self._build_result_url(query)

        for index, item in enumerate(raw_results):
            if not isinstance(item, dict):
                logger.warning(
                    f"leakcheck: skipping non-dict item in response: "
                    f"{type(item).__name__}"
                )
                continue

            raw_sources = item.get("sources", [])
            if not isinstance(raw_sources, list):
                raw_sources = []

            sources = [source for source in raw_sources if isinstance(source, dict)]
            line_value = item.get("line", "")
            if not isinstance(line_value, str):
                line_value = ""

            if not sources and not line_value:
                logger.warning("leakcheck: skipping malformed entry with no usable fields")
                continue

            primary_source = sources[0] if sources else {}
            source_name = str(primary_source.get("name", "")).strip()
            paste_id = source_name or f"entry_{index}"
            date = str(primary_source.get("date", "")).strip()
            tags = [
                str(source.get("name", "")).strip()
                for source in sources
                if str(source.get("name", "")).strip()
            ][:5]

            results.append(PasteResult(
                paste_id=paste_id,
                url=result_url,
                date=date,
                size=len(line_value),
                tags=tags,
            ))

        return results


_searcher = PasteSearch()


async def search_paste(query: str, use_cache: bool = True) -> list[PasteResult]:
    """
    Search LeakCheck for breach entries matching a target.

    Args:
        query: Email address, username, domain, or IP address
        use_cache: Whether to use cached results

    Returns:
        List of PasteResult sorted by date descending
    """
    return await _searcher.search(query, use_cache=use_cache)

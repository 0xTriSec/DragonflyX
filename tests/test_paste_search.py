"""Tests for the paste search module."""

from __future__ import annotations

import httpx
import pytest
import respx

from dragonflyX.modules.paste_search import search_paste


class TestSearchReturnsPasteResults:
    """Tests for successful paste search responses."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_search_returns_paste_results(self) -> None:
        """Mock LeakCheck returns one result; verify all fields are parsed correctly."""
        route = respx.get("https://leakcheck.io/api/public?check=test%40example.com")
        route.return_value = httpx.Response(
            200,
            json={
                "success": True,
                "found": 1,
                "result": [
                    {
                        "sources": [{"name": "TestBreach2024", "date": "2024-01-15"}],
                        "line": "test@example.com:password123",
                    }
                ],
            },
        )

        results = await search_paste("test@example.com", use_cache=False)

        assert len(results) == 1
        assert results[0].paste_id == "TestBreach2024"
        assert results[0].date == "2024-01-15"
        assert results[0].size == len("test@example.com:password123")
        assert results[0].tags == ["TestBreach2024"]


class TestSearchEmptyResponse:
    """Tests for empty and zero-result responses."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_search_empty_response_returns_empty_list(self) -> None:
        """Empty API result returns an empty list, not an exception."""
        route = respx.get("https://leakcheck.io/api/public?check=test%40example.com")
        route.return_value = httpx.Response(200, json={"success": True, "found": 0, "result": []})

        results = await search_paste("test@example.com", use_cache=False)

        assert results == []


class TestSearchErrorHandling:
    """Tests for graceful degradation under error conditions."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_search_api_unreachable_returns_empty_list(self) -> None:
        """Network error returns empty list without propagating the exception."""
        route = respx.get("https://leakcheck.io/api/public?check=unreachable")
        route.side_effect = httpx.ConnectError("Connection refused")

        results = await search_paste("unreachable", use_cache=False)

        assert results == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_search_malformed_entries_are_skipped(self) -> None:
        """API responses with malformed entries are tolerated; valid ones are returned."""
        route = respx.get("https://leakcheck.io/api/public?check=test")
        route.return_value = httpx.Response(
            200,
            json={
                "success": True,
                "found": 2,
                "result": [
                    {},
                    {"sources": [{"name": "ValidBreach", "date": ""}], "line": "x"},
                ],
            },
        )

        results = await search_paste("test", use_cache=False)

        assert len(results) == 1
        assert results[0].paste_id == "ValidBreach"


class TestSanitizeQuery:
    """Tests for query sanitization and path traversal blocking."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_sanitize_query_strips_path_traversal(self) -> None:
        """Path traversal sequences are stripped before the request is sent."""
        route = respx.get("https://leakcheck.io/api/public?check=etcpasswd")
        route.return_value = httpx.Response(200, json={"success": True, "found": 0, "result": []})

        results = await search_paste("../../etc/passwd", use_cache=False)

        assert results == []
        assert route.called
        assert route.calls.last.request.url.params["check"] == "etcpasswd"


class TestResultOrdering:
    """Tests for result ordering and sorting."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_results_sorted_newest_first(self) -> None:
        """Results are sorted by date descending (newest first)."""
        route = respx.get("https://leakcheck.io/api/public?check=test")
        route.return_value = httpx.Response(
            200,
            json={
                "success": True,
                "found": 2,
                "result": [
                    {"sources": [{"name": "OlderBreach", "date": "2023-01-01"}], "line": "older"},
                    {"sources": [{"name": "NewerBreach", "date": "2024-06-15"}], "line": "newer"},
                ],
            },
        )

        results = await search_paste("test", use_cache=False)

        assert len(results) == 2
        assert results[0].date == "2024-06-15"
        assert results[1].date == "2023-01-01"


class TestPasteResultDataclass:
    """Tests for the PasteResult dataclass."""

    def test_paste_result_model_dump(self) -> None:
        """PasteResult.model_dump() serializes to a plain dict."""
        from dragonflyX.modules.paste_search import PasteResult

        result = PasteResult(
            paste_id="TestBreach2024",
            url="https://leakcheck.io/search?query=test%40example.com",
            date="2024-01-15",
            size=28,
            tags=["TestBreach2024"],
        )

        dumped = result.model_dump()
        assert isinstance(dumped, dict)
        assert dumped["paste_id"] == "TestBreach2024"
        assert dumped["url"] == "https://leakcheck.io/search?query=test%40example.com"
        assert dumped["date"] == "2024-01-15"
        assert dumped["size"] == 28
        assert dumped["tags"] == ["TestBreach2024"]

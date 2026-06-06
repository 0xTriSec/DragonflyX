"""Tests for URL analysis module."""

from __future__ import annotations

import httpx
import pytest
import respx

from dragonflyX.core.cache import cache
from dragonflyX.modules.url_analysis import analyze_url


class TestAnalyzeURL:
    """Tests for URL analysis."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_analyze_url_complete_flow(self) -> None:
        """Test analyze_url with complete flow (submit + poll for both providers)."""
        # URLScan submit
        respx.post("https://urlscan.io/api/v1/scan/").mock(
            return_value=httpx.Response(200, json={"uuid": "test-uuid-123"})
        )
        # URLScan poll (success)
        respx.get("https://urlscan.io/api/v1/result/test-uuid-123/").mock(
            return_value=httpx.Response(200, json={
                "verdicts": {"overall": {"malicious": False, "score": 0}},
                "task": {"time": "2024-01-01T00:00:00"},
                "lists": {"ips": [], "domains": []},
            })
        )
        # VT submit
        respx.post("https://www.virustotal.com/api/v3/urls").mock(
            return_value=httpx.Response(200, json={"data": {"id": "vt-analysis-id"}})
        )
        # VT poll (completed)
        respx.get("https://www.virustotal.com/api/v3/analyses/vt-analysis-id").mock(
            return_value=httpx.Response(200, json={
                "attributes": {
                    "status": "completed",
                    "stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 70,
                        "undetected": 3,
                    },
                    "date": 1700000000,
                },
                "meta": {"url_info": {"url": "https://example.com"}},
            })
        )

        result = await analyze_url("https://example.com", use_cache=False)

        assert result.url == "https://example.com"
        assert result.risk_level in ("malicious", "suspicious", "clean", "unknown")
        assert result.urlscan is not None
        assert result.virustotal is not None

    @respx.mock
    @pytest.mark.asyncio
    async def test_analyze_url_safelinks_decoded(self) -> None:
        """Test that SafeLinks URLs are auto-decoded."""
        safelinks_url = (
            "https://nam01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.com%2Fmalware"
            "&data=abc123&sdata=def456"
        )
        expected_decoded = "https://evil.com/malware"

        # URLScan submit
        respx.post("https://urlscan.io/api/v1/scan/").mock(
            return_value=httpx.Response(200, json={"uuid": "test-uuid-456"})
        )
        # URLScan poll (success)
        respx.get("https://urlscan.io/api/v1/result/test-uuid-456/").mock(
            return_value=httpx.Response(200, json={
                "verdicts": {"overall": {"malicious": False, "score": 0}},
                "task": {"time": "2024-01-01T00:00:00"},
                "lists": {"ips": [], "domains": []},
            })
        )
        # VT submit
        respx.post("https://www.virustotal.com/api/v3/urls").mock(
            return_value=httpx.Response(200, json={"data": {"id": "vt-id-456"}})
        )
        # VT poll
        respx.get("https://www.virustotal.com/api/v3/analyses/vt-id-456").mock(
            return_value=httpx.Response(200, json={
                "attributes": {
                    "status": "completed",
                    "stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 70,
                        "undetected": 3,
                    },
                    "date": 1700000000,
                },
                "meta": {"url_info": {"url": expected_decoded}},
            })
        )

        result = await analyze_url(safelinks_url, use_cache=False)

        assert result.decoded_url == expected_decoded
        assert result.encoding_type == "safelinks"

    @respx.mock
    @pytest.mark.asyncio
    async def test_analyze_url_urlscan_malicious(self) -> None:
        """Test that URLScan malicious verdict results in malicious risk."""
        # URLScan submit
        respx.post("https://urlscan.io/api/v1/scan/").mock(
            return_value=httpx.Response(200, json={"uuid": "malicious-uuid"})
        )
        # URLScan poll - MALICIOUS
        respx.get("https://urlscan.io/api/v1/result/malicious-uuid/").mock(
            return_value=httpx.Response(200, json={
                "verdicts": {"overall": {"malicious": True, "score": 80}},
                "task": {"time": "2024-01-01T00:00:00"},
                "lists": {"ips": ["1.2.3.4"], "domains": ["evil.com"]},
            })
        )
        # VT submit
        respx.post("https://www.virustotal.com/api/v3/urls").mock(
            return_value=httpx.Response(200, json={"data": {"id": "vt-mal-id"}})
        )
        # VT poll - clean
        respx.get("https://www.virustotal.com/api/v3/analyses/vt-mal-id").mock(
            return_value=httpx.Response(200, json={
                "attributes": {
                    "status": "completed",
                    "stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 70,
                        "undetected": 3,
                    },
                    "date": 1700000000,
                },
                "meta": {},
            })
        )

        result = await analyze_url("https://suspicious-site.com", use_cache=False)

        # URLScan malicious should trigger malicious risk
        assert result.risk_level == "malicious"
        assert result.urlscan is not None
        assert result.urlscan.verdict_malicious is True

    @respx.mock
    @pytest.mark.asyncio
    async def test_analyze_url_vt_malicious_increases_score(self) -> None:
        """Test that VT with multiple malicious engines increases score."""
        cache.delete(cache.make_key("url_analysis", "https://example.com"))
        cache.delete(cache.make_key("urlscan", "https://example.com"))
        cache.delete(cache.make_key("urlscan_vt", "https://example.com"))
        # URLScan submit
        respx.post("https://urlscan.io/api/v1/scan/").mock(
            return_value=httpx.Response(200, json={"uuid": "vt-score-uuid"})
        )
        # URLScan poll - clean
        respx.get("https://urlscan.io/api/v1/result/vt-score-uuid/").mock(
            return_value=httpx.Response(200, json={
                "verdicts": {"overall": {"malicious": False, "score": 0}},
                "task": {"time": "2024-01-01T00:00:00"},
                "lists": {"ips": [], "domains": []},
            })
        )
        # VT submit
        respx.post("https://www.virustotal.com/api/v3/urls").mock(
            return_value=httpx.Response(200, json={"data": {"id": "vt-score-id"}})
        )
        # VT poll - 3 malicious
        respx.get("https://www.virustotal.com/api/v3/analyses/vt-score-id").mock(
            return_value=httpx.Response(200, json={
                "attributes": {
                    "status": "completed",
                    "stats": {
                        "malicious": 3,
                        "suspicious": 1,
                        "harmless": 60,
                        "undetected": 9,
                    },
                    "date": 1700000000,
                },
                "meta": {},
            })
        )

        result = await analyze_url("https://example.com", use_cache=False)

        # 3 malicious from VT = +20 score (at least)
        assert result.risk_score >= 20
        assert result.virustotal is not None
        assert result.virustotal.malicious == 3

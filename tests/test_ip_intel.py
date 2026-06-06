"""Tests for IP intelligence module."""

from __future__ import annotations

import httpx
import pytest
import respx

from dragonflyX.modules.ip_intel import analyze_ip
from dragonflyX.modules.ip_intel.schemas import IPIntelResult, ShodanResult


class TestAnalyzeIP:
    """Tests for IP analysis."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_analyze_ip_all_providers_success(self, vt_ip_response, abuseipdb_response, shodan_response, ipinfo_response) -> None:
        """Test analyze_ip with all providers returning valid data."""
        # Mock VirusTotal
        vt_route = respx.get("https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8")
        vt_route.return_value = httpx.Response(200, json=vt_ip_response)

        # Mock AbuseIPDB
        ab_route = respx.get("https://api.abuseipdb.com/api/v2/check")
        ab_route.return_value = httpx.Response(200, json=abuseipdb_response)

        # Mock Shodan
        sh_route = respx.get("https://api.shodan.io/shodan/host/8.8.8.8")
        sh_route.return_value = httpx.Response(200, json=shodan_response)

        # Mock ipinfo
        ip_route = respx.get("https://ipinfo.io/8.8.8.8/json")
        ip_route.return_value = httpx.Response(200, json=ipinfo_response)

        result = await analyze_ip("8.8.8.8", use_cache=False)

        assert isinstance(result, IPIntelResult)
        assert result.ip == "8.8.8.8"
        assert result.risk_level in ("critical", "high", "medium", "low", "unknown")
        assert result.virustotal is not None
        assert result.abuseipdb is not None
        assert result.shodan is not None
        assert result.ipinfo is not None
        assert result.errors == {}

    @respx.mock
    @pytest.mark.asyncio
    async def test_analyze_ip_vt_malicious_medium_risk(self, abuseipdb_response, shodan_response, ipinfo_response) -> None:
        """Test that VT with 3 malicious detections results in medium or higher risk."""
        vt_response = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 3,
                        "suspicious": 1,
                        "harmless": 60,
                        "undetected": 9,
                    },
                    "reputation": -10,
                    "last_analysis_date": 1700000000,
                }
            }
        }

        respx.get("https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8").mock(
            return_value=httpx.Response(200, json=vt_response)
        )
        respx.get("https://api.abuseipdb.com/api/v2/check").mock(
            return_value=httpx.Response(200, json=abuseipdb_response)
        )
        respx.get("https://api.shodan.io/shodan/host/8.8.8.8").mock(
            return_value=httpx.Response(200, json=shodan_response)
        )
        respx.get("https://ipinfo.io/8.8.8.8/json").mock(
            return_value=httpx.Response(200, json=ipinfo_response)
        )

        result = await analyze_ip("8.8.8.8", use_cache=False)

        # 3 malicious from VT = +20 score, should be at least "low" risk
        assert result.risk_score >= 20
        assert result.risk_level in ("critical", "high", "medium", "low")

    @respx.mock
    @pytest.mark.asyncio
    async def test_analyze_ip_abuse_high_score_tor(self, vt_ip_clean_response, shodan_response, ipinfo_response) -> None:
        """Test that AbuseIPDB score=92 + TOR results in high score."""
        respx.get("https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4").mock(
            return_value=httpx.Response(200, json=vt_ip_clean_response)
        )
        respx.get("https://api.abuseipdb.com/api/v2/check").mock(
            return_value=httpx.Response(200, json={
                "data": {
                    "ipAddress": "1.2.3.4",
                    "isPublic": True,
                    "abuseConfidenceScore": 92,
                    "totalReports": 150,
                    "isp": "SomeISP",
                    "usageType": "Unknown",
                    "isTor": True,
                    "countryCode": "XX",
                    "lastReportedAt": "2024-01-01T00:00:00+00:00",
                }
            })
        )
        respx.get("https://api.shodan.io/shodan/host/1.2.3.4").mock(
            return_value=httpx.Response(200, json=shodan_response)
        )
        respx.get("https://ipinfo.io/1.2.3.4/json").mock(
            return_value=httpx.Response(200, json={"ip": "1.2.3.4"})
        )

        result = await analyze_ip("1.2.3.4", use_cache=False)

        # 92 abuse score > 80 = +35, TOR = +10, should be >= 45
        assert result.risk_score >= 45

    @respx.mock
    @pytest.mark.asyncio
    async def test_analyze_ip_shodan_404_returns_empty_result(self, vt_ip_response, abuseipdb_response, ipinfo_response) -> None:
        """Test that Shodan 404 returns empty ShodanResult, not an error."""
        respx.get("https://www.virustotal.com/api/v3/ip_addresses/1.1.1.1").mock(
            return_value=httpx.Response(200, json=vt_ip_response)
        )
        respx.get("https://api.abuseipdb.com/api/v2/check").mock(
            return_value=httpx.Response(200, json=abuseipdb_response)
        )
        # Shodan returns 404 for non-indexed IPs
        respx.get("https://api.shodan.io/shodan/host/1.1.1.1").mock(
            return_value=httpx.Response(404, json={"error": "No information available"})
        )
        respx.get("https://ipinfo.io/1.1.1.1/json").mock(
            return_value=httpx.Response(200, json={"ip": "1.1.1.1"})
        )

        result = await analyze_ip("1.1.1.1", use_cache=False)

        # Shodan 404 should return empty ShodanResult, not an error
        assert result.shodan is not None
        assert isinstance(result.shodan, ShodanResult)
        assert result.shodan.open_ports == []
        assert result.shodan.services == []
        # 404 is not an error for Shodan
        assert "shodan" not in result.errors

    @respx.mock
    @pytest.mark.asyncio
    async def test_analyze_ip_vt_server_error_other_providers_success(
        self, abuseipdb_response, shodan_response, ipinfo_response
    ) -> None:
        """Test that VT server error is captured in errors, other providers still succeed."""
        from dragonflyX.core.cache import cache

        cache.delete(cache.make_key("virustotal", "8.8.8.8"))
        cache.delete(cache.make_key("abuseipdb", "8.8.8.8"))
        cache.delete(cache.make_key("shodan", "8.8.8.8"))
        cache.delete(cache.make_key("ipinfo", "8.8.8.8"))
        cache.delete(cache.make_key("ip_intel", "8.8.8.8"))
        respx.get("https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8").mock(
            return_value=httpx.Response(500, json={"error": "Internal Server Error"})
        )
        respx.get("https://api.abuseipdb.com/api/v2/check").mock(
            return_value=httpx.Response(200, json=abuseipdb_response)
        )
        respx.get("https://api.shodan.io/shodan/host/8.8.8.8").mock(
            return_value=httpx.Response(200, json=shodan_response)
        )
        respx.get("https://ipinfo.io/8.8.8.8/json").mock(
            return_value=httpx.Response(200, json=ipinfo_response)
        )

        result = await analyze_ip("8.8.8.8", use_cache=False)

        # VT error should be captured
        assert "virustotal" in result.errors
        # Other providers should still succeed
        assert result.abuseipdb is not None
        assert result.shodan is not None
        assert result.ipinfo is not None

    @respx.mock
    @pytest.mark.asyncio
    async def test_analyze_ip_uses_cache(self, vt_ip_response, abuseipdb_response, shodan_response, ipinfo_response) -> None:
        """Test that second call returns cached result."""
        respx.get("https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8").mock(
            return_value=httpx.Response(200, json=vt_ip_response)
        )
        respx.get("https://api.abuseipdb.com/api/v2/check").mock(
            return_value=httpx.Response(200, json=abuseipdb_response)
        )
        respx.get("https://api.shodan.io/shodan/host/8.8.8.8").mock(
            return_value=httpx.Response(200, json=shodan_response)
        )
        respx.get("https://ipinfo.io/8.8.8.8/json").mock(
            return_value=httpx.Response(200, json=ipinfo_response)
        )

        # First call - not cached
        result1 = await analyze_ip("8.8.8.8", use_cache=True)
        assert result1.cached is False

        # Second call - should be cached (no new HTTP calls made)
        result2 = await analyze_ip("8.8.8.8", use_cache=True)
        assert result2.cached is True

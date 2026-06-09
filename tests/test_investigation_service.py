"""Tests for investigation service orchestration."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from dragonflyX.core.exceptions import InvalidInput, NetworkError
from dragonflyX.modules.investigation.schemas import InvestigationResult
from dragonflyX.modules.investigation.service import investigate


def _make_ipintel_result(ip: str = "185.220.101.45") -> Any:
    """Build a minimal IPIntelResult for mocking analyze_ip()."""
    from dragonflyX.modules.ip_intel.schemas import GeoInfo, IPInfoResult, IPIntelResult, ShodanResult

    return IPIntelResult(
        ip=ip,
        risk_level="medium",
        risk_score=45,
        ipinfo=IPInfoResult(
            hostname="mail.evil.com",
            geo=GeoInfo(country="US", org="AS12345 Some ISP"),
        ),
        shodan=ShodanResult(
            open_ports=[80, 443],
        ),
    )


def _make_dns_result(domain: str = "evil.com") -> Any:
    """Build a minimal DNSResult for mocking."""
    from dragonflyX.modules.dns_tools import DNSResult

    return DNSResult(
        domain=domain,
        a=["185.220.101.45"],
        whois={
            "registrar": "Evil Registrar",
            "creation_date": "2020-01-01",
            "emails": ["admin@evil.com"],
            "name_servers": ["ns1.evil.com", "ns2.evil.com"],
        },
        subdomains=[],
    )


@pytest.mark.asyncio
async def test_investigate_ip_complete_flow() -> None:
    """IP investigation populates IP intel, pivots to domain, runs paste and dorks."""
    ip_result = _make_ipintel_result()

    with (
        patch("dragonflyX.modules.investigation.service.detect_target") as mock_detect,
        patch("dragonflyX.modules.investigation.service.analyze_ip", new_callable=AsyncMock) as mock_ip,
        patch("dragonflyX.modules.investigation.service.lookup_domain", new_callable=AsyncMock) as mock_dns,
        patch("dragonflyX.modules.investigation.service.search_paste", new_callable=AsyncMock) as mock_paste,
        patch("dragonflyX.modules.investigation.service.generate_dorks", new_callable=AsyncMock) as mock_dorks,
    ):
        from dragonflyX.modules.investigation.schemas import InvestigationTarget

        mock_detect.return_value = InvestigationTarget(
            raw_input="185.220.101.45",
            input_type="ip",
            normalized="185.220.101.45",
        )
        mock_ip.return_value = ip_result
        mock_dns.return_value = _make_dns_result("evil.com")
        mock_paste.return_value = []
        mock_dorks.return_value = []

        result = await investigate("185.220.101.45", use_cache=False)

    assert result.target_type == "ip"
    assert result.ip_risk_level == "medium"
    assert result.ip_risk_score == 45
    assert "evil.com" in result.domains
    assert len(result.steps) >= 4


@pytest.mark.asyncio
async def test_investigate_domain_complete_flow() -> None:
    """Domain investigation populates DNS, pivots to IP intel, runs paste and dorks."""
    from dragonflyX.modules.investigation.schemas import InvestigationTarget

    with (
        patch("dragonflyX.modules.investigation.service.detect_target") as mock_detect,
        patch("dragonflyX.modules.investigation.service.lookup_domain", new_callable=AsyncMock) as mock_dns,
        patch("dragonflyX.modules.investigation.service.analyze_ip", new_callable=AsyncMock) as mock_ip,
        patch("dragonflyX.modules.investigation.service.search_paste", new_callable=AsyncMock) as mock_paste,
        patch("dragonflyX.modules.investigation.service.generate_dorks", new_callable=AsyncMock) as mock_dorks,
    ):
        mock_detect.return_value = InvestigationTarget(
            raw_input="evil.com",
            input_type="domain",
            normalized="evil.com",
        )
        mock_dns.return_value = _make_dns_result("evil.com")
        mock_ip.return_value = _make_ipintel_result("185.220.101.45")
        mock_paste.return_value = []
        mock_dorks.return_value = []

        result = await investigate("evil.com", use_cache=False)

    assert result.target_type == "domain"
    assert "185.220.101.45" in result.ip_addresses


@pytest.mark.asyncio
async def test_investigate_email_complete_flow() -> None:
    """Email investigation extracts domain, runs DNS, IP intel, paste, dorks."""
    from dragonflyX.modules.investigation.schemas import InvestigationTarget

    with (
        patch("dragonflyX.modules.investigation.service.detect_target") as mock_detect,
        patch("dragonflyX.modules.investigation.service.lookup_domain", new_callable=AsyncMock) as mock_dns,
        patch("dragonflyX.modules.investigation.service.analyze_ip", new_callable=AsyncMock) as mock_ip,
        patch("dragonflyX.modules.investigation.service.search_paste", new_callable=AsyncMock) as mock_paste,
        patch("dragonflyX.modules.investigation.service.generate_dorks", new_callable=AsyncMock) as mock_dorks,
    ):
        mock_detect.return_value = InvestigationTarget(
            raw_input="admin@evil.com",
            input_type="email",
            normalized="admin@evil.com",
        )
        mock_dns.return_value = _make_dns_result("evil.com")
        mock_ip.return_value = _make_ipintel_result("185.220.101.45")
        mock_paste.return_value = []
        mock_dorks.return_value = []

        result = await investigate("admin@evil.com", use_cache=False)

    assert result.target_type == "email"
    assert "evil.com" in result.domains


@pytest.mark.asyncio
async def test_investigate_step_failure_does_not_crash() -> None:
    """A NetworkError in one step is captured; investigation still returns a result."""
    from dragonflyX.core.exceptions import NetworkError
    from dragonflyX.modules.investigation.schemas import InvestigationTarget

    with (
        patch("dragonflyX.modules.investigation.service.detect_target") as mock_detect,
        patch("dragonflyX.modules.investigation.service.analyze_ip", new_callable=AsyncMock) as mock_ip,
        patch("dragonflyX.modules.investigation.service.lookup_domain", new_callable=AsyncMock) as mock_dns,
        patch("dragonflyX.modules.investigation.service.search_paste", new_callable=AsyncMock) as mock_paste,
        patch("dragonflyX.modules.investigation.service.generate_dorks", new_callable=AsyncMock) as mock_dorks,
    ):
        mock_detect.return_value = InvestigationTarget(
            raw_input="185.220.101.45",
            input_type="ip",
            normalized="185.220.101.45",
        )
        mock_ip.side_effect = NetworkError(url="http://test", reason="connection failed")
        mock_dns.return_value = _make_dns_result()
        mock_paste.return_value = []
        mock_dorks.return_value = []

        result = await investigate("185.220.101.45", use_cache=False)

    assert "ip_intelligence" in result.errors or "pivot_ip_intel" in result.errors
    assert result.target_type == "ip"
    assert len(result.steps) >= 1


@pytest.mark.asyncio
async def test_investigate_invalid_target_raises() -> None:
    """investigate() raises InvalidInput for unclassifiable input."""
    with (
        patch("dragonflyX.modules.investigation.service.detect_target") as mock_detect,
    ):
        from dragonflyX.core.exceptions import InvalidInput

        mock_detect.side_effect = InvalidInput(
            input_type="investigation target",
            value="not valid!!!",
            reason="must be an IP address, domain name, or email address",
        )

        with pytest.raises(InvalidInput):
            await investigate("not valid!!!", use_cache=False)


@pytest.mark.asyncio
async def test_investigate_uses_cache_on_second_call() -> None:
    """Second call with same target returns cached result."""
    from dragonflyX.core.cache import cache
    from dragonflyX.modules.investigation.schemas import InvestigationTarget

    cache_key = cache.make_key("investigation", "evil.com")

    # Ensure clean state
    try:
        cache.delete(cache_key)
    except Exception:
        pass

    with (
        patch("dragonflyX.modules.investigation.service.detect_target") as mock_detect,
        patch("dragonflyX.modules.investigation.service.lookup_domain", new_callable=AsyncMock) as mock_dns,
        patch("dragonflyX.modules.investigation.service.search_paste", new_callable=AsyncMock) as mock_paste,
        patch("dragonflyX.modules.investigation.service.generate_dorks", new_callable=AsyncMock) as mock_dorks,
    ):
        mock_detect.return_value = InvestigationTarget(
            raw_input="evil.com",
            input_type="domain",
            normalized="evil.com",
        )
        mock_dns.return_value = _make_dns_result("evil.com")
        mock_paste.return_value = []
        mock_dorks.return_value = []

        first = await investigate("evil.com", use_cache=True)
        assert first.cached is False

        second = await investigate("evil.com", use_cache=True)
        assert second.cached is True

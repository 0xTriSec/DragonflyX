"""Tests for DNS subdomain enumeration."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import dns.resolver
import pytest

from dragonflyX.modules.dns_tools import enumerate_subdomains, lookup_domain


class TestEnumerateSubdomains:
    """Tests for subdomain enumeration behavior."""

    @pytest.mark.asyncio
    async def test_enumerate_subdomains_finds_results(self) -> None:
        """Resolved subdomains are returned with their IP addresses."""

        def resolve(self, hostname: str, record_type: str):
            if hostname == "randomwildcard.example.com" and record_type == "A":
                raise dns.resolver.NXDOMAIN()
            if hostname == "www.example.com" and record_type == "A":
                answer = MagicMock()
                answer.__str__ = MagicMock(return_value="1.2.3.4")
                return [answer]
            raise dns.resolver.NXDOMAIN()

        with patch("dragonflyX.modules.dns_tools._detect_wildcard", return_value=None), patch(
            "dns.resolver.Resolver.resolve",
            new=resolve,
        ):
            results = await enumerate_subdomains("example.com")

        assert "www.example.com" in [result.hostname for result in results]
        www_result = next(result for result in results if result.hostname == "www.example.com")
        assert www_result.ip_addresses == ["1.2.3.4"]

    @pytest.mark.asyncio
    async def test_wildcard_detection_marks_results(self) -> None:
        """Subdomains matching the wildcard IP are marked as wildcard results."""

        def resolve(self, hostname: str, record_type: str):
            if hostname == "www.example.com" and record_type == "A":
                answer = MagicMock()
                answer.__str__ = MagicMock(return_value="9.9.9.9")
                return [answer]
            raise dns.resolver.NXDOMAIN()

        with patch("dragonflyX.modules.dns_tools._detect_wildcard", return_value="9.9.9.9"), patch(
            "dns.resolver.Resolver.resolve",
            new=resolve,
        ):
            results = await enumerate_subdomains("example.com")

        assert len(results) == 1
        assert results[0].hostname == "www.example.com"
        assert results[0].is_wildcard is True

    @pytest.mark.asyncio
    async def test_no_subdomains_returns_empty_list(self) -> None:
        """If all lookups fail, enumeration returns an empty list."""

        def resolve(self, hostname: str, record_type: str):
            raise dns.resolver.NXDOMAIN()

        with patch("dragonflyX.modules.dns_tools._detect_wildcard", return_value=None), patch(
            "dns.resolver.Resolver.resolve",
            new=resolve,
        ):
            results = await enumerate_subdomains("example.com")

        assert results == []

    @pytest.mark.asyncio
    async def test_subdomain_results_sorted_alphabetically(self) -> None:
        """Enumeration results are sorted by hostname."""

        def resolve(self, hostname: str, record_type: str):
            if hostname == "api.example.com" and record_type == "A":
                answer = MagicMock()
                answer.__str__ = MagicMock(return_value="2.2.2.2")
                return [answer]
            if hostname == "admin.example.com" and record_type == "A":
                answer = MagicMock()
                answer.__str__ = MagicMock(return_value="1.1.1.1")
                return [answer]
            raise dns.resolver.NXDOMAIN()

        with patch("dragonflyX.modules.dns_tools._detect_wildcard", return_value=None), patch(
            "dns.resolver.Resolver.resolve",
            new=resolve,
        ):
            results = await enumerate_subdomains("example.com")

        assert len(results) == 2
        assert results[0].hostname < results[1].hostname

    @pytest.mark.asyncio
    async def test_lookup_domain_without_subdomains_has_empty_list(self) -> None:
        """Regular DNS lookup keeps subdomains empty when enumeration is disabled."""

        def resolve(hostname: str, record_type: str):
            if hostname == "example.com" and record_type == "A":
                answer = MagicMock()
                answer.__str__ = MagicMock(return_value="93.184.216.34")
                return [answer]
            raise dns.resolver.NoAnswer()

        with patch("dns.resolver.resolve", new=resolve), patch("whois.whois", return_value=None):
            result = await lookup_domain("example.com", use_cache=False, enumerate_subs=False)

        assert result.subdomains == []

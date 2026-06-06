"""Tests for the Google Dorks generator module."""

from __future__ import annotations

import pytest

from dragonflyX.core.exceptions import InvalidInput
from dragonflyX.modules.dorks_generator import (
    DorkResult,
    generate_dorks,
)


class TestDetectTargetType:
    """Tests for target type detection."""

    @pytest.mark.asyncio
    async def test_detect_domain(self) -> None:
        result = await generate_dorks("example.com")
        assert all(isinstance(r, DorkResult) for r in result)

    @pytest.mark.asyncio
    async def test_detect_subdomain(self) -> None:
        result = await generate_dorks("sub.example.com")
        assert all(isinstance(r, DorkResult) for r in result)

    @pytest.mark.asyncio
    async def test_detect_email(self) -> None:
        result = await generate_dorks("admin@example.com")
        assert all(isinstance(r, DorkResult) for r in result)

    @pytest.mark.asyncio
    async def test_detect_generic(self) -> None:
        result = await generate_dorks("Acme Corporation")
        assert all(isinstance(r, DorkResult) for r in result)


class TestDorkOutput:
    """Tests for dork output structure and content."""

    @pytest.mark.asyncio
    async def test_dork_count_domain(self) -> None:
        """Domain targets produce at least 10 dork queries."""
        results = await generate_dorks("example.com")
        assert len(results) >= 10

    @pytest.mark.asyncio
    async def test_dork_urls_are_valid_google_urls(self) -> None:
        """All result URLs must be valid Google search URLs."""
        results = await generate_dorks("example.com")
        for dork in results:
            assert dork.url.startswith("https://www.google.com/search?q=")

    @pytest.mark.asyncio
    async def test_domain_dorks_use_site_operator(self) -> None:
        """Domain targets produce at least one site:-scoped dork."""
        results = await generate_dorks("example.com")
        site_queries = [d for d in results if "site:example.com" in d.query]
        assert len(site_queries) >= 1

    @pytest.mark.asyncio
    async def test_email_special_characters_are_url_encoded(self) -> None:
        """Email @ must appear as %40 in URLs, not raw, for {target} dorks."""
        results = await generate_dorks("test@example.com")
        target_dorks = [d for d in results if d.category != "INFRASTRUCTURE"]
        for dork in target_dorks:
            assert "@" not in dork.url, f"Raw @ found in URL: {dork.url}"
            assert "%40" in dork.url, f"Expected %40 in URL: {dork.url}"

    @pytest.mark.asyncio
    async def test_empty_target_raises(self) -> None:
        """Empty target string raises InvalidInput."""
        with pytest.raises(InvalidInput):
            await generate_dorks("")


class TestDorkCategories:
    """Tests for dork category structure."""

    @pytest.mark.asyncio
    async def test_results_grouped_by_category(self) -> None:
        """Results must be organized into the four expected categories."""
        results = await generate_dorks("example.com")
        categories = {d.category for d in results}
        expected = {
            "IDENTITY",
            "CREDENTIALS & LEAKS",
            "INFRASTRUCTURE",
            "TECHNICAL EXPOSURE",
        }
        assert categories == expected

    @pytest.mark.asyncio
    async def test_identity_category_present(self) -> None:
        """IDENTITY category must be present for all target types."""
        for target in ["example.com", "admin@example.com", "johndoe", "Acme Corp"]:
            results = await generate_dorks(target)
            categories = {d.category for d in results}
            assert "IDENTITY" in categories

    @pytest.mark.asyncio
    async def test_credentials_category_present(self) -> None:
        """CREDENTIALS & LEAKS category must be present for all target types."""
        for target in ["example.com", "admin@example.com", "johndoe", "Acme Corp"]:
            results = await generate_dorks(target)
            categories = {d.category for d in results}
            assert "CREDENTIALS & LEAKS" in categories

    @pytest.mark.asyncio
    async def test_technical_category_present(self) -> None:
        """TECHNICAL EXPOSURE category must be present for all target types."""
        for target in ["example.com", "admin@example.com", "johndoe", "Acme Corp"]:
            results = await generate_dorks(target)
            categories = {d.category for d in results}
            assert "TECHNICAL EXPOSURE" in categories

    @pytest.mark.asyncio
    async def test_infrastructure_category_requires_domain(self) -> None:
        """INFRASTRUCTURE category only appears for domain/email targets."""
        results_username = await generate_dorks("johndoe99")
        username_categories = {d.category for d in results_username}
        assert "INFRASTRUCTURE" not in username_categories

        results_email = await generate_dorks("admin@example.com")
        email_categories = {d.category for d in results_email}
        assert "INFRASTRUCTURE" in email_categories

        results_domain = await generate_dorks("example.com")
        domain_categories = {d.category for d in results_domain}
        assert "INFRASTRUCTURE" in domain_categories

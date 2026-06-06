"""Tests for the phone intelligence module."""

from __future__ import annotations

import pytest

from dragonflyX.core.cache import cache
from dragonflyX.core.exceptions import InvalidInput
from dragonflyX.modules.phone_intel import lookup_phone


class TestPhoneIntel:
    """Tests for offline phone metadata lookups."""

    @pytest.mark.asyncio
    async def test_valid_mobile_number(self) -> None:
        """Vietnam mobile number returns valid metadata."""
        cache.delete(cache.make_key("phone_intel", "+84901234567"))

        result = await lookup_phone("+84901234567", use_cache=True)

        assert result.is_valid is True
        assert result.country_code == "VN"
        assert result.line_type == "mobile"

    @pytest.mark.asyncio
    async def test_valid_us_number(self) -> None:
        """US number returns valid metadata."""
        cache.delete(cache.make_key("phone_intel", "+14155552671"))

        result = await lookup_phone("+14155552671", use_cache=False)

        assert result.country_code == "US"
        assert result.is_valid is True

    @pytest.mark.asyncio
    async def test_invalid_number_raises(self) -> None:
        """Invalid input raises InvalidInput."""
        with pytest.raises(InvalidInput):
            await lookup_phone("not-a-phone", use_cache=False)

    @pytest.mark.asyncio
    async def test_formatted_e164(self) -> None:
        """E.164 formatting is preserved for valid numbers."""
        cache.delete(cache.make_key("phone_intel", "+84901234567"))

        result = await lookup_phone("+84901234567", use_cache=False)

        assert result.formatted_e164 == "+84901234567"

    @pytest.mark.asyncio
    async def test_caching(self) -> None:
        """Second lookup returns cached result."""
        cache.delete(cache.make_key("phone_intel", "+84901234567"))

        first = await lookup_phone("+84901234567", use_cache=True)
        second = await lookup_phone("+84901234567", use_cache=True)

        assert first.cached is False
        assert second.cached is True

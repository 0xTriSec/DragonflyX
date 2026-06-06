"""Tests for hash check module."""

from __future__ import annotations

import tempfile

import httpx
import pytest
import respx

from dragonflyX.core.cache import cache
from dragonflyX.core.exceptions import InvalidInput
from dragonflyX.modules.hash_check import check_file, check_hash


class TestCheckHash:
    """Tests for hash checking."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_check_hash_not_found(self) -> None:
        """Test check_hash with VT returning 404 - unknown risk."""
        hash_val = "0000000000000000000000000000000000000001"
        respx.get(f"https://www.virustotal.com/api/v3/files/{hash_val}").mock(
            return_value=httpx.Response(404, json={"error": {"code": "NotFoundError"}})
        )

        result = await check_hash(hash_val, use_cache=False)

        assert result.risk_level == "unknown"
        assert result.risk_score == 0
        assert result.hash_value == hash_val

    @respx.mock
    @pytest.mark.asyncio
    async def test_check_hash_critical(self, vt_hash_malicious) -> None:
        """Test check_hash with 12 malicious - critical risk."""
        hash_val = "0000000000000000000000000000000000000000"  # 40 char SHA1 placeholder
        respx.get(f"https://www.virustotal.com/api/v3/files/{hash_val}").mock(
            return_value=httpx.Response(200, json=vt_hash_malicious)
        )

        result = await check_hash(hash_val, use_cache=False)

        assert result.risk_level == "critical"
        assert result.risk_score == 90
        assert result.malicious_count == 12

    @respx.mock
    @pytest.mark.asyncio
    async def test_check_hash_medium(self) -> None:
        """Test check_hash with 3 malicious - medium risk."""
        hash_val = "d41d8cd98f00b204e9800998ecf8427e"  # MD5
        cache_key = cache.make_key("hash_check", hash_val)
        cache.delete(cache_key)
        vt_response = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 3,
                        "suspicious": 0,
                        "harmless": 60,
                        "undetected": 10,
                    },
                    "type_description": "Unknown",
                    "size": None,
                    "meaningful_name": None,
                    "first_submission_date": None,
                    "last_analysis_date": None,
                    "last_analysis_results": {},
                    "tags": [],
                }
            }
        }
        respx.get(f"https://www.virustotal.com/api/v3/files/{hash_val}").mock(
            return_value=httpx.Response(200, json=vt_response)
        )

        result = await check_hash(hash_val, use_cache=False)

        # 3 malicious >= 1 but < 5 = medium risk
        assert result.risk_level == "medium"

    @respx.mock
    @pytest.mark.asyncio
    async def test_check_hash_low(self) -> None:
        """Test check_hash with 0 malicious, 0 suspicious - low risk."""
        hash_val = "d41d8cd98f00b204e9800998ecf8427e"  # MD5
        cache_key = cache.make_key("hash_check", hash_val)
        cache.delete(cache_key)
        vt_response = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 70,
                        "undetected": 3,
                    },
                    "type_description": "Unknown",
                    "size": None,
                    "meaningful_name": None,
                    "first_submission_date": None,
                    "last_analysis_date": None,
                    "last_analysis_results": {},
                    "tags": [],
                }
            }
        }
        respx.get(f"https://www.virustotal.com/api/v3/files/{hash_val}").mock(
            return_value=httpx.Response(200, json=vt_response)
        )

        result = await check_hash(hash_val, use_cache=False)

        # 0 malicious, 0 suspicious = low risk
        assert result.risk_level == "low"
        assert result.risk_score == 10

    @respx.mock
    @pytest.mark.asyncio
    async def test_check_file_computes_sha256(self) -> None:
        """Test check_file computes SHA256 of temp file and calls VT."""
        content = b"Test content for hashing"

        vt_response = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 70,
                        "undetected": 3,
                    },
                    "type_description": "Text",
                    "size": len(content),
                    "meaningful_name": "test.txt",
                    "first_submission_date": None,
                    "last_analysis_date": None,
                    "last_analysis_results": {},
                    "tags": [],
                }
            }
        }

        # Mock VT to accept any hash
        respx.get(url__startswith="https://www.virustotal.com/api/v3/files/").mock(
            return_value=httpx.Response(200, json=vt_response)
        )

        # Create temp file
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            f.write(content)
            f.flush()
            temp_path = f.name

        try:
            result = await check_file(temp_path, use_cache=False)
            assert result.hash_type == "sha256"
            assert result.file_type == "Text"
            assert result.file_size == len(content)
        finally:
            import os
            os.unlink(temp_path)

    @respx.mock
    @pytest.mark.asyncio
    async def test_check_file_not_found(self) -> None:
        """Test check_file with non-existent path raises InvalidInput."""
        with pytest.raises(InvalidInput):
            await check_file("/nonexistent/path/to/file.exe", use_cache=False)

    @respx.mock
    @pytest.mark.asyncio
    async def test_check_hash_caching(self) -> None:
        """Test that second call returns cached result."""
        hash_val = "d41d8cd98f00b204e9800998ecf8427e"
        cache_key = cache.make_key("hash_check", hash_val)
        cache.delete(cache_key)
        vt_response = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 70,
                        "undetected": 3,
                    },
                    "type_description": "Unknown",
                    "size": None,
                    "meaningful_name": None,
                    "first_submission_date": None,
                    "last_analysis_date": None,
                    "last_analysis_results": {},
                    "tags": [],
                }
            }
        }

        route = respx.get(f"https://www.virustotal.com/api/v3/files/{hash_val}").mock(
            return_value=httpx.Response(200, json=vt_response)
        )

        # First call
        result1 = await check_hash(hash_val, use_cache=True)
        assert result1.cached is False
        assert route.call_count == 1

        # Second call - should be cached
        result2 = await check_hash(hash_val, use_cache=True)
        assert result2.cached is True
        # No additional HTTP call
        assert route.call_count == 1

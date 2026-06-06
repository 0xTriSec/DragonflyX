"""Tests for input validators."""

from __future__ import annotations

import tempfile

import pytest

from dragonflyX.core.exceptions import InvalidInput
from dragonflyX.core.validators import (
    compute_file_hash,
    detect_hash_type,
    validate_domain,
    validate_hash,
    validate_ip,
    validate_url,
    validate_username,
)


class TestValidateIP:
    """Tests for IP validation."""

    @pytest.mark.parametrize(
        "ip",
        [
            "8.8.8.8",
            "192.168.1.1",
            "0.0.0.0",
            "255.255.255.255",
            "10.0.0.1",
        ],
    )
    def test_valid_ipv4(self, ip: str) -> None:
        result = validate_ip(ip)
        assert result == ip

    @pytest.mark.parametrize("ip", ["::1", "2001:db8::1", "::ffff:192.168.1.1"])
    def test_valid_ipv6(self, ip: str) -> None:
        result = validate_ip(ip)
        assert result == ip.lower()

    @pytest.mark.parametrize(
        "ip",
        [
            "not-an-ip",
            "999.999.999.999",
            "",
            " ",
            "192.168.1",
            "192.168.1.1.1",
        ],
    )
    def test_invalid_ip(self, ip: str) -> None:
        with pytest.raises(InvalidInput):
            validate_ip(ip)


class TestValidateURL:
    """Tests for URL validation."""

    @pytest.mark.parametrize(
        "url",
        [
            "http://example.com",
            "https://example.com",
            "https://example.com/path",
            "https://example.com/path?q=1",
            "https://example.com/path?q=1&r=2",
            "http://localhost:8080",
        ],
    )
    def test_valid_url(self, url: str) -> None:
        result = validate_url(url)
        assert result == url

    @pytest.mark.parametrize("url", ["ftp://example.com", "example.com", "not a url", ""])
    def test_invalid_url(self, url: str) -> None:
        with pytest.raises(InvalidInput):
            validate_url(url)


class TestValidateHash:
    """Tests for hash validation."""

    def test_valid_md5(self) -> None:
        hash_str = "d41d8cd98f00b204e9800998ecf8427e"
        normalized, hash_type = validate_hash(hash_str)
        assert normalized == hash_str
        assert hash_type == "md5"

    def test_valid_sha1(self) -> None:
        hash_str = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        normalized, hash_type = validate_hash(hash_str)
        assert hash_type == "sha1"

    def test_valid_sha256(self) -> None:
        hash_str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        normalized, hash_type = validate_hash(hash_str)
        assert hash_type == "sha256"

    def test_valid_sha512(self) -> None:
        hash_str = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        normalized, hash_type = validate_hash(hash_str)
        assert hash_type == "sha512"

    def test_normalizes_to_lowercase(self) -> None:
        hash_str = "D41D8CD98F00B204E9800998ECF8427E"
        normalized, hash_type = validate_hash(hash_str)
        assert normalized == "d41d8cd98f00b204e9800998ecf8427e"

    @pytest.mark.parametrize(
        "hash_str",
        [
            "toolonghash",
            "short",
            "d41d8cd98f00b204e9800998ecf842",  # 31 chars
            "d41d8cd98f00b204e9800998ecf8427e00",  # 36 chars
        ],
    )
    def test_invalid_length(self, hash_str: str) -> None:
        with pytest.raises(InvalidInput):
            validate_hash(hash_str)

    def test_invalid_characters(self) -> None:
        with pytest.raises(InvalidInput):
            validate_hash("ghijklmnopqrstuvwxyz0123456789")

    def test_empty_string(self) -> None:
        with pytest.raises(InvalidInput):
            validate_hash("")


class TestValidateDomain:
    """Tests for domain validation."""

    @pytest.mark.parametrize(
        "domain",
        [
            "google.com",
            "example.org",
            "sub.domain.co.uk",
            "github.com",
            "api.example.com",
        ],
    )
    def test_valid_domain(self, domain: str) -> None:
        result = validate_domain(domain)
        assert result == domain.lower()

    @pytest.mark.parametrize(
        "domain",
        [
            "nodot",
            "has space.com",
            "",
            "has\ttab.com",
            ".startswithdot.com",
        ],
    )
    def test_invalid_domain(self, domain: str) -> None:
        with pytest.raises(InvalidInput):
            validate_domain(domain)


class TestValidateUsername:
    """Tests for username validation."""

    @pytest.mark.parametrize(
        "username",
        [
            "johndoe",
            "john_doe",
            "john.doe",
            "a",
            "user123",
            "a" * 39,
        ],
    )
    def test_valid_username(self, username: str) -> None:
        result = validate_username(username)
        assert result == username

    def test_empty_username(self) -> None:
        with pytest.raises(InvalidInput):
            validate_username("")

    def test_too_long_username(self) -> None:
        with pytest.raises(InvalidInput):
            validate_username("a" * 40)

    def test_invalid_characters(self) -> None:
        with pytest.raises(InvalidInput):
            validate_username("user@name")


class TestComputeFileHash:
    """Tests for file hash computation."""

    def test_compute_hash(self) -> None:
        """Create a temp file with known content, verify SHA256."""
        content = b"Hello, World!"
        # SHA256 of "Hello, World!"
        expected = "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(content)
            f.flush()
            result = compute_file_hash(f.name)

        assert result == expected

    def test_file_not_found(self) -> None:
        with pytest.raises(InvalidInput):
            compute_file_hash("/nonexistent/path/to/file.txt")


class TestDetectHashType:
    """Tests for hash type detection."""

    @pytest.mark.parametrize(
        "hash_str,expected",
        [
            ("d41d8cd98f00b204e9800998ecf8427e", "md5"),
            ("da39a3ee5e6b4b0d3255bfef95601890afd80709", "sha1"),
            (
                "e3b0c44298fc1c149afbf4c8996fb924"
                "27ae41e4649b934ca495991b7852b855",
                "sha256",
            ),
            (
                "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
                "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
                "sha512",
            ),
        ],
    )
    def test_detect_type(self, hash_str: str, expected: str) -> None:
        result = detect_hash_type(hash_str)
        assert result == expected

    def test_detect_invalid(self) -> None:
        result = detect_hash_type("not-a-hash")
        assert result is None

    def test_detect_empty(self) -> None:
        result = detect_hash_type("")
        assert result is None

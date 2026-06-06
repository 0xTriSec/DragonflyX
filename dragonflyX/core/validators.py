"""Input validation utilities - stdlib only."""

from __future__ import annotations

import hashlib
import ipaddress
import re
from pathlib import Path
from urllib.parse import urlparse

from dragonflyX.core.exceptions import InvalidInput


def validate_ip(value: str) -> str:
    """
    Validate and normalize an IP address.

    Args:
        value: IP address string (IPv4 or IPv6)

    Returns:
        Normalized IP address string

    Raises:
        InvalidInput: If value is not a valid IP address

    Examples:
        >>> validate_ip('8.8.8.8')
        '8.8.8.8'
        >>> validate_ip('::1')
        '::1'
        >>> validate_ip('192.168.1.1')
        '192.168.1.1'
    """
    try:
        ip = ipaddress.ip_address(value.strip())
        return str(ip)
    except ValueError as e:
        raise InvalidInput(
            input_type="IP address",
            value=value,
            reason="not a valid IP address format",
        ) from e


def validate_url(value: str) -> str:
    """
    Validate a URL.

    Args:
        value: URL string to validate

    Returns:
        Stripped URL string

    Raises:
        InvalidInput: If URL is not properly formatted

    Examples:
        >>> validate_url('https://example.com')
        'https://example.com'
        >>> validate_url('http://example.com/path?q=1')
        'http://example.com/path?q=1'
    """
    try:
        parsed = urlparse(value.strip())
        if parsed.scheme not in ("http", "https"):
            raise InvalidInput(
                input_type="URL",
                value=value,
                reason="scheme must be http or https",
            )
        if not parsed.netloc:
            raise InvalidInput(
                input_type="URL",
                value=value,
                reason="missing network location",
            )
        return value.strip()
    except Exception as e:
        if isinstance(e, InvalidInput):
            raise
        raise InvalidInput(
            input_type="URL",
            value=value,
            reason="not a valid URL format",
        ) from e


def validate_hash(value: str) -> tuple[str, str]:
    """
    Validate a hash string and determine its type.

    Args:
        value: Hash string to validate (MD5, SHA1, SHA256, or SHA512)

    Returns:
        Tuple of (normalized_hash, hash_type)

    Raises:
        InvalidInput: If hash is invalid (wrong length, non-hex chars)

    Examples:
        >>> validate_hash('d41d8cd98f00b204e9800998ecf8427e')
        ('d41d8cd98f00b204e9800998ecf8427e', 'md5')
        >>> validate_hash('da39a3ee5e6b4b0d3255bfef95601890afd80709')
        ('da39a3ee5e6b4b0d3255bfef95601890afd80709', 'sha1')
    """
    normalized = value.lower().strip()

    # Check if hash contains only valid hex characters
    if not re.match(r"^[a-f0-9]+$", normalized):
        raise InvalidInput(
            input_type="hash",
            value=value,
            reason="contains non-hexadecimal characters",
        )

    # Determine hash type by length
    length = len(normalized)
    hash_types = {
        32: "md5",
        40: "sha1",
        64: "sha256",
        128: "sha512",
    }

    if length not in hash_types:
        raise InvalidInput(
            input_type="hash",
            value=value,
            reason=f"invalid length {length} (expected 32=MD5, 40=SHA1, 64=SHA256, or 128=SHA512)",
        )

    return normalized, hash_types[length]


def validate_domain(value: str) -> str:
    """
    Validate a domain name.

    Args:
        value: Domain string to validate

    Returns:
        Lowercase normalized domain

    Raises:
        InvalidInput: If domain is not valid
    """
    normalized = value.lower().strip()

    # Check for empty value
    if not normalized:
        raise InvalidInput(
            input_type="domain",
            value=value,
            reason="domain cannot be empty",
        )

    if normalized.startswith("."):
        raise InvalidInput(
            input_type="domain",
            value=value,
            reason="domain cannot start with a dot",
        )

    # Check for valid characters
    if not re.match(r"^[a-z0-9.\-]+$", normalized):
        raise InvalidInput(
            input_type="domain",
            value=value,
            reason="contains invalid characters",
        )

    # Must contain at least one dot (for TLD)
    if "." not in normalized:
        raise InvalidInput(
            input_type="domain",
            value=value,
            reason="must contain at least one dot",
        )

    # Check for spaces
    if " " in normalized:
        raise InvalidInput(
            input_type="domain",
            value=value,
            reason="cannot contain spaces",
        )

    return normalized


def validate_username(value: str) -> str:
    """
    Validate a username.

    Args:
        value: Username string to validate

    Returns:
        Stripped username

    Raises:
        InvalidInput: If username is invalid

    Examples:
        >>> validate_username('johndoe')
        'johndoe'
        >>> validate_username('john_doe')
        'john_doe'
    """
    if not value:
        raise InvalidInput(
            input_type="username",
            value=value,
            reason="username cannot be empty",
        )

    stripped = value.strip()

    # Check length (1-39 characters)
    if len(stripped) > 39:
        raise InvalidInput(
            input_type="username",
            value=value,
            reason="must be 39 characters or less",
        )

    # Check valid characters (alphanumeric, underscore, dot, hyphen)
    if not re.match(r"^[a-zA-Z0-9_.\-]+$", stripped):
        raise InvalidInput(
            input_type="username",
            value=value,
            reason=(
                "contains invalid characters "
                "(only alphanumeric, underscore, dot, hyphen allowed)"
            ),
        )

    return stripped


def compute_file_hash(path: str) -> str:
    """
    Compute SHA256 hash of a file.

    Args:
        path: Path to the file

    Returns:
        SHA256 hash as hexadecimal string

    Raises:
        InvalidInput: If file does not exist or cannot be read
    """
    file_path = Path(path)

    if not file_path.exists():
        raise InvalidInput(
            input_type="file path",
            value=path,
            reason="file not found",
        )

    if not file_path.is_file():
        raise InvalidInput(
            input_type="file path",
            value=path,
            reason="path is not a file",
        )

    sha256_hash = hashlib.sha256()

    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256_hash.update(chunk)
    except PermissionError as e:
        raise InvalidInput(
            input_type="file path",
            value=path,
            reason="permission denied",
        ) from e
    except OSError as e:
        raise InvalidInput(
            input_type="file path",
            value=path,
            reason=f"cannot read file: {e}",
        ) from e

    return sha256_hash.hexdigest()


def detect_hash_type(value: str) -> str | None:
    """
    Detect hash type from string length.

    Args:
        value: Hash string to analyze

    Returns:
        Hash type name ('md5', 'sha1', 'sha256', 'sha512') or None if unknown

    Examples:
        >>> detect_hash_type('d41d8cd98f00b204e9800998ecf8427e')
        'md5'
        >>> detect_hash_type('invalid')
        None
    """
    normalized = value.lower().strip()

    # Check if it looks like a hex string
    if not re.match(r"^[a-f0-9]+$", normalized):
        return None

    length = len(normalized)
    hash_types = {
        32: "md5",
        40: "sha1",
        64: "sha256",
        128: "sha512",
    }

    return hash_types.get(length)

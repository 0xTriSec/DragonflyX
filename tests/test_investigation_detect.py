"""Tests for investigation module input detection and pivot helpers."""

from __future__ import annotations

import pytest

from dragonflyX.core.exceptions import InvalidInput
from dragonflyX.modules.investigation import detect_target
from dragonflyX.modules.investigation.pivots import (
    extract_domain_from_hostname,
    extract_whois_emails,
)
from dragonflyX.modules.dns_tools import DNSResult


class TestDetectTarget:
    """Tests for detect_target() input classification."""

    def test_detect_ip_v4(self) -> None:
        """IPv4 address is classified as ip."""
        result = detect_target("185.220.101.45")
        assert result.input_type == "ip"
        assert result.normalized == "185.220.101.45"
        assert result.raw_input == "185.220.101.45"

    def test_detect_ip_v6(self) -> None:
        """IPv6 address is classified as ip."""
        result = detect_target("2001:db8::1")
        assert result.input_type == "ip"
        assert result.normalized == "2001:db8::1"

    def test_detect_domain(self) -> None:
        """Domain name is classified as domain."""
        result = detect_target("evil-domain.com")
        assert result.input_type == "domain"
        assert result.normalized == "evil-domain.com"

    def test_detect_domain_case_normalized(self) -> None:
        """Domain name is lowercased in normalized output."""
        result = detect_target("EXAMPLE.COM")
        assert result.input_type == "domain"
        assert result.normalized == "example.com"

    def test_detect_email(self) -> None:
        """Email address is classified as email."""
        result = detect_target("admin@evil-domain.com")
        assert result.input_type == "email"
        assert result.normalized == "admin@evil-domain.com"

    def test_detect_email_whitespace_stripped(self) -> None:
        """Leading/trailing whitespace is stripped before classification."""
        result = detect_target("  user@example.com  ")
        assert result.input_type == "email"
        assert result.normalized == "user@example.com"

    def test_detect_invalid_raises(self) -> None:
        """Unclassifiable input raises InvalidInput."""
        with pytest.raises(InvalidInput) as exc_info:
            detect_target("not valid input!!!")
        assert "must be an IP address, domain name, or email address" in str(
            exc_info.value.user_friendly
        )

    def test_detect_empty_string_raises(self) -> None:
        """Empty string raises InvalidInput."""
        with pytest.raises(InvalidInput):
            detect_target("")

    def test_detect_empty_string_whitespace_raises(self) -> None:
        """Whitespace-only string raises InvalidInput."""
        with pytest.raises(InvalidInput):
            detect_target("   ")


class TestExtractDomainFromHostname:
    """Tests for extract_domain_from_hostname()."""

    def test_extract_subdomain(self) -> None:
        """mail.evil.com -> evil.com."""
        assert extract_domain_from_hostname("mail.evil.com") == "evil.com"

    def test_extract_simple_domain(self) -> None:
        """evil.com -> evil.com."""
        assert extract_domain_from_hostname("evil.com") == "evil.com"

    def test_extract_localhost(self) -> None:
        """localhost -> None."""
        assert extract_domain_from_hostname("localhost") is None

    def test_extract_case_normalized(self) -> None:
        """Hostname is lowercased before processing."""
        assert extract_domain_from_hostname("MAIL.EVIL.COM") == "evil.com"

    def test_extract_trailing_dot(self) -> None:
        """Hostname with trailing dot is handled."""
        assert extract_domain_from_hostname("mail.evil.com.") == "evil.com"


class TestExtractWhoisEmails:
    """Tests for extract_whois_emails()."""

    def test_extract_whois_emails_found(self) -> None:
        """WHOIS dict with emails key returns those emails."""
        dns_result = DNSResult(
            domain="evil.com",
            whois={"emails": ["admin@evil.com", "hostmaster@evil.com"]},
        )
        emails = extract_whois_emails(dns_result)
        assert emails == ["admin@evil.com", "hostmaster@evil.com"]

    def test_extract_whois_emails_empty(self) -> None:
        """DNS result with no WHOIS data returns empty list."""
        dns_result = DNSResult(domain="evil.com")
        assert extract_whois_emails(dns_result) == []

    def test_extract_whois_emails_none_whois(self) -> None:
        """DNS result with whois=None returns empty list."""
        dns_result = DNSResult(domain="evil.com", whois={})
        assert extract_whois_emails(dns_result) == []

    def test_extract_whois_emails_list_form(self) -> None:
        """WHOIS emails field may be a list."""
        dns_result = DNSResult(
            domain="evil.com",
            whois={"email": ["single@evil.com"]},
        )
        emails = extract_whois_emails(dns_result)
        assert "single@evil.com" in emails

    def test_extract_whois_emails_deduplicated(self) -> None:
        """Duplicate emails are removed."""
        dns_result = DNSResult(
            domain="evil.com",
            whois={"emails": ["a@evil.com", "a@evil.com", "b@evil.com"]},
        )
        emails = extract_whois_emails(dns_result)
        assert emails.count("a@evil.com") == 1

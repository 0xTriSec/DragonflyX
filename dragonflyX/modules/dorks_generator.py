"""Google Dorks generator for OSINT reconnaissance."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Literal

from dragonflyX.core.exceptions import InvalidInput

DORK_CATEGORIES: list[str] = [
    "IDENTITY",
    "CREDENTIALS & LEAKS",
    "INFRASTRUCTURE",
    "TECHNICAL EXPOSURE",
]


@dataclass
class DorkResult:
    """Single dork query result."""

    category: str
    description: str
    query: str
    url: str

    def model_dump(self, *, mode: str = "json") -> dict:
        """Serialize to dict for report generation."""
        return asdict(self)


def _detect_target_type(target: str) -> Literal["domain", "email", "username", "generic"]:
    """
    Detect the type of target string.

    Args:
        target: Raw input string

    Returns:
        One of: "domain", "email", "username", "generic"
    """
    stripped = target.strip()

    if not stripped:
        return "generic"

    if "@" in stripped and "." in stripped:
        return "email"

    if "." in stripped and " " not in stripped and stripped.count(".") <= 3:
        return "domain"

    if " " in stripped:
        return "generic"

    return "username"


def _extract_domain_from_email(email: str) -> str | None:
    """
    Extract domain from an email address.

    Args:
        email: Email string

    Returns:
        Domain part or None
    """
    parts = email.strip().split("@")
    if len(parts) == 2 and parts[1]:
        domain = parts[1].strip().rstrip(".")
        if domain:
            return domain
    return None


# --- Dork pattern definitions ---

_IDENTITY_PATTERNS = [
    ('"{target}"', "Exact match search across all sources"),
    ('"{target}" site:linkedin.com', "Find LinkedIn profile for the target"),
    ('"{target}" site:github.com', "Find GitHub repositories or profiles"),
    ('"{target}" site:twitter.com OR site:x.com', "Find Twitter/X profile or mentions"),
]

_CREDENTIALS_PATTERNS = [
    ('"{target}" password OR passwd OR credentials', "Search for leaked credentials"),
    ('"{target}" filetype:sql OR filetype:csv OR filetype:xlsx', "Exposed database files"),
    ('"{target}" site:pastebin.com OR site:gist.github.com', "Pastes and code snippets"),
]

_INFRASTRUCTURE_PATTERNS = [
    ("site:{domain} filetype:pdf OR filetype:docx", "Exposed documents"),
    ("site:{domain} inurl:admin OR inurl:login OR inurl:panel", "Admin and login pages"),
    ("site:{domain} inurl:config OR inurl:backup OR inurl:.env", "Configuration and backup files"),
]

_TECHNICAL_PATTERNS = [
    ('"{target}" intext:password OR intext:api_key OR intext:token', "Hardcoded secrets in source"),
    ('"{target}" filetype:log', "Exposed log files"),
    ('"{target}" "internal use only" OR "confidential"', "Sensitive internal documents"),
    ('"{target}" ext:php OR ext:asp inurl:id=', "Vulnerable endpoints"),
]


def _url_encode(text: str) -> str:
    """
    URL-encode a dork query string.

    Args:
        text: Raw query string

    Returns:
        URL-encoded string suitable for Google search URL
    """
    return (
        text.replace(" ", "+")
        .replace("@", "%40")
        .replace('"', "%22")
        .replace("(", "%28")
        .replace(")", "%29")
        .replace(":", "%3A")
        .replace("|", "%7C")
    )


def _generate_dorks(
    target: str,
    target_type: Literal["domain", "email", "username", "generic"],
) -> list[DorkResult]:
    """
    Generate all dork queries for the given target and type.

    Args:
        target: The search target
        target_type: Detected type of target

    Returns:
        List of DorkResult sorted by category order
    """
    results: list[DorkResult] = []

    domain: str | None = None
    if target_type == "domain":
        domain = target
    elif target_type == "email":
        domain = _extract_domain_from_email(target)

    def fill(template: str) -> str:
        result = template.replace("{target}", target)
        if domain:
            result = result.replace("{domain}", domain)
        return result

    # IDENTITY patterns — always included
    for query, description in _IDENTITY_PATTERNS:
        filled = fill(query)
        results.append(DorkResult(
            category="IDENTITY",
            description=description,
            query=filled,
            url=f"https://www.google.com/search?q={_url_encode(filled)}",
        ))

    # CREDENTIALS & LEAKS — always included
    for query, description in _CREDENTIALS_PATTERNS:
        filled = fill(query)
        results.append(DorkResult(
            category="CREDENTIALS & LEAKS",
            description=description,
            query=filled,
            url=f"https://www.google.com/search?q={_url_encode(filled)}",
        ))

    # INFRASTRUCTURE — only when domain is known (domain or email target)
    if domain:
        for query, description in _INFRASTRUCTURE_PATTERNS:
            filled = fill(query)
            results.append(DorkResult(
                category="INFRASTRUCTURE",
                description=description,
                query=filled,
                url=f"https://www.google.com/search?q={_url_encode(filled)}",
            ))

    # TECHNICAL EXPOSURE — always included
    for query, description in _TECHNICAL_PATTERNS:
        filled = fill(query)
        results.append(DorkResult(
            category="TECHNICAL EXPOSURE",
            description=description,
            query=filled,
            url=f"https://www.google.com/search?q={_url_encode(filled)}",
        ))

    return results


async def generate_dorks(target: str) -> list[DorkResult]:
    """
    Generate OSINT Google Dorks for a given target.

    Args:
        target: Domain, email, username, full name, or organization

    Raises:
        InvalidInput: If target is empty or whitespace only
    """
    stripped = target.strip()
    if not stripped:
        raise InvalidInput(
            input_type="target",
            value=target,
            reason="target string cannot be empty",
        )
    target_type = _detect_target_type(stripped)
    return _generate_dorks(stripped, target_type)

"""Pydantic schemas for the investigation module."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field


@dataclass
class InvestigationTarget:
    """
    Represents a parsed investigation target with detected type.

    Attributes:
        raw_input: The original string provided by the user
        input_type: Detected type — ip, domain, or email
        normalized: Cleaned version ready for API calls
    """

    raw_input: str
    input_type: Literal["ip", "domain", "email"]
    normalized: str


class InvestigationStep(BaseModel):
    """
    Result of a single investigation step.

    Attributes:
        name: Human-readable step name
        status: completed, skipped, or failed
        duration_ms: Time taken in milliseconds
        summary: One-line summary of what was found
        error: Error message if status is failed
    """

    name: str
    status: Literal["completed", "skipped", "failed"]
    duration_ms: int = 0
    summary: str = ""
    error: str = ""


class InvestigationResult(BaseModel):
    """
    Complete investigation result combining all pivot findings.
    """

    target: str
    target_type: Literal["ip", "domain", "email"]
    query_time: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    # IP intelligence
    ip_addresses: list[str] = Field(default_factory=list)
    ip_risk_level: str = "unknown"
    ip_risk_score: int = 0
    ip_isp: str = ""
    ip_country: str = ""
    open_ports: list[int] = Field(default_factory=list)

    # Domain intelligence
    domains: list[str] = Field(default_factory=list)
    registrar: str = ""
    whois_emails: list[str] = Field(default_factory=list)
    nameservers: list[str] = Field(default_factory=list)
    domain_created: str = ""

    # Subdomain intelligence
    subdomains: list[str] = Field(default_factory=list)

    # Breach intelligence
    paste_hits: int = 0
    paste_sources: list[str] = Field(default_factory=list)

    # OSINT links
    dork_urls: list[str] = Field(default_factory=list)

    # Investigation metadata
    steps: list[InvestigationStep] = Field(default_factory=list)
    errors: dict[str, str] = Field(default_factory=dict)
    cached: bool = False

    @property
    def overall_risk(self) -> str:
        """Derive overall risk from IP risk level."""
        return self.ip_risk_level if self.ip_risk_level != "unknown" else "unknown"

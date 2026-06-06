"""Pydantic schemas for IP intelligence module."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, Field

type RiskLevel = Literal["critical", "high", "medium", "low", "unknown"]


class GeoInfo(BaseModel):
    """Geographic and network information."""

    country: str | None = None
    city: str | None = None
    org: str | None = None
    asn: str | None = None
    latitude: float | None = None
    longitude: float | None = None


class PortInfo(BaseModel):
    """Information about an open port."""

    port: int
    protocol: str | None = None
    service: str | None = None
    banner: str | None = None


class VulnInfo(BaseModel):
    """Vulnerability information."""

    cve_id: str
    cvss: float | None = None
    summary: str | None = None


class VirusTotalIPResult(BaseModel):
    """VirusTotal IP analysis result."""

    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    total_engines: int = 0
    last_analysis_date: datetime | None = None
    reputation: int = 0


class AbuseIPDBResult(BaseModel):
    """AbuseIPDB analysis result."""

    abuse_score: int = 0
    total_reports: int = 0
    last_reported: datetime | None = None
    isp: str | None = None
    usage_type: str | None = None
    is_tor: bool = False
    country_code: str | None = None


class ShodanResult(BaseModel):
    """Shodan analysis result."""

    open_ports: list[int] = Field(default_factory=list)
    services: list[PortInfo] = Field(default_factory=list)
    vulns: list[VulnInfo] = Field(default_factory=list)
    hostnames: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    last_update: str | None = None
    os: str | None = None


class IPInfoResult(BaseModel):
    """ipinfo.io analysis result."""

    geo: GeoInfo = Field(default_factory=GeoInfo)
    hostname: str | None = None
    is_bogon: bool = False


class IPIntelResult(BaseModel):
    """Combined IP intelligence result from all providers."""

    ip: str
    query_time: datetime = Field(default_factory=lambda: datetime.now(UTC))
    risk_level: RiskLevel = "unknown"
    risk_score: int = 0
    virustotal: VirusTotalIPResult | None = None
    abuseipdb: AbuseIPDBResult | None = None
    shodan: ShodanResult | None = None
    ipinfo: IPInfoResult | None = None
    errors: dict[str, str] = Field(default_factory=dict)
    cached: bool = False

    def summary(self) -> dict:
        """Return a summary dict of the IP analysis."""
        return {
            "ip": self.ip,
            "risk": f"{self.risk_level} ({self.risk_score}/100)",
            "vt_malicious": self.virustotal.malicious if self.virustotal else "N/A",
            "abuse_score": self.abuseipdb.abuse_score if self.abuseipdb else "N/A",
            "open_ports": self.shodan.open_ports if self.shodan else [],
            "country": self.ipinfo.geo.country if self.ipinfo else "N/A",
        }

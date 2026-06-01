"""Pydantic schemas for URL analysis module."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field


type URLRiskLevel = Literal["malicious", "suspicious", "clean", "unknown"]


class URLScanResult(BaseModel):
    """URLScan.io scan result."""

    scan_id: str
    report_url: str
    screenshot_url: str | None = None
    verdict_malicious: bool = False
    verdict_score: int = 0
    ips_found: list[str] = Field(default_factory=list)
    domains_found: list[str] = Field(default_factory=list)
    submit_time: datetime | None = None


class VTURLResult(BaseModel):
    """VirusTotal URL analysis result."""

    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    total_engines: int = 0
    last_analysis_date: datetime | None = None
    final_url: str | None = None


class URLAnalysisResult(BaseModel):
    """Combined URL analysis result from all providers."""

    url: str
    decoded_url: str | None = None
    encoding_type: str | None = None
    query_time: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    risk_level: URLRiskLevel = "unknown"
    risk_score: int = 0
    urlscan: URLScanResult | None = None
    virustotal: VTURLResult | None = None
    errors: dict[str, str] = Field(default_factory=dict)
    cached: bool = False

"""Pydantic schemas for hash check module."""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, Field

from dragonflyX.modules.ip_intel.schemas import RiskLevel


class EngineResult(BaseModel):
    """Individual engine detection result."""

    engine_name: str
    category: str
    result: str | None = None


class HashCheckResult(BaseModel):
    """Hash check result from VirusTotal."""

    hash_value: str
    hash_type: str
    query_time: datetime = Field(default_factory=lambda: datetime.now(UTC))
    risk_level: RiskLevel = "unknown"
    risk_score: int = 0
    file_type: str | None = None
    file_size: int | None = None
    meaningful_name: str | None = None
    malicious_count: int = 0
    suspicious_count: int = 0
    total_engines: int = 0
    detection_ratio: str = "0/0"
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    top_detections: list[EngineResult] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    errors: dict[str, str] = Field(default_factory=dict)
    cached: bool = False

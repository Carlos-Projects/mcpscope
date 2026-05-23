from __future__ import annotations
from datetime import datetime, timezone
from pydantic import BaseModel, Field


class ScanRun(BaseModel):
    id: str
    scanner: str
    target: str | None = None
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    raw_file: str | None = None
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ScanHistory(BaseModel):
    scans: list[ScanRun] = []
    total_findings: int = 0
    total_critical: int = 0
    total_high: int = 0
    total_medium: int = 0
    total_low: int = 0
    total_info: int = 0

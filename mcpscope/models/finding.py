from __future__ import annotations
from enum import Enum
from datetime import datetime, timezone
from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_ORDER = {s: i for i, s in enumerate(Severity)}
SEVERITY_COLORS = {
    Severity.CRITICAL: "#dc2626",
    Severity.HIGH: "#ea580c",
    Severity.MEDIUM: "#ca8a04",
    Severity.LOW: "#2563eb",
    Severity.INFO: "#6b7280",
}


class Finding(BaseModel):
    id: str | None = None
    scan_id: str
    scanner: str
    tool_name: str
    tool_version: str | None = None
    severity: Severity
    title: str
    description: str | None = None
    recommendation: str | None = None
    cvss_score: float | None = None
    cve_id: str | None = None
    raw_data: dict | None = None
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def severity_order(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 99)

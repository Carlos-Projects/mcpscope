from __future__ import annotations
from enum import Enum
from datetime import datetime, timezone
from pydantic import BaseModel, Field


class EventSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class SecurityEvent(BaseModel):
    id: str | None = None
    event_type: str
    severity: str
    message: str
    source: str = "mcpguard"
    tool: str | None = None
    details: dict | None = None
    blocked: bool = True
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

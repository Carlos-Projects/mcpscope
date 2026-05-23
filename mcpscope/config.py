from __future__ import annotations
import json
import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

DEFAULT_CONFIG_PATH = Path.home() / ".mcpscope" / "config.json"


@dataclass
class Settings:
    db_path: str = str(Path.home() / ".mcpscope" / "mcpscope.db")
    host: str = "127.0.0.1"
    port: int = 8080
    log_level: str = "info"
    auto_refresh_seconds: int = 30
    api_key: str | None = None
    webhook_urls: list[str] = field(default_factory=list)
    slack_webhook_url: str | None = None
    max_upload_mb: int = 50

    @classmethod
    def load(cls, path: str | Path | None = None) -> Settings:
        path = Path(path) if path else DEFAULT_CONFIG_PATH
        if path.exists():
            try:
                with open(path) as f:
                    data = json.load(f)
                return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})
            except (json.JSONDecodeError, TypeError):
                pass
        return cls()

    def save(self, path: str | Path | None = None):
        path = Path(path) if path else DEFAULT_CONFIG_PATH
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(self.as_dict(), f, indent=2)

    def as_dict(self) -> dict:
        return {k: getattr(self, k) for k in self.__dataclass_fields__}

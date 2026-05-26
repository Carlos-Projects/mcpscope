from __future__ import annotations
import json
import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any

DEFAULT_CONFIG_PATH = Path.home() / ".mcpscope" / "config.json"

ENV_PREFIX = "MCPSCOPE_"
FIELD_TYPE_MAP: dict[str, type] = {
    "port": int,
    "auto_refresh_seconds": int,
    "max_upload_mb": int,
    "log_json": bool,
}


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
    dashboard_password: str | None = None
    log_json: bool = False

    @classmethod
    def load(cls, path: str | Path | None = None) -> Settings:
        data: dict[str, Any] = {}
        path = Path(path) if path else DEFAULT_CONFIG_PATH
        if path.exists():
            try:
                with open(path) as f:
                    data.update(json.load(f))
            except (json.JSONDecodeError, TypeError):
                pass
        for field_name in cls.__dataclass_fields__:
            env_key = f"{ENV_PREFIX}{field_name.upper()}"
            if env_key in os.environ:
                raw = os.environ[env_key]
                field_type = FIELD_TYPE_MAP.get(field_name, str)
                if field_type is bool:
                    data[field_name] = raw.lower() in ("1", "true", "yes")
                else:
                    data[field_name] = field_type(raw)
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})

    def save(self, path: str | Path | None = None):
        path = Path(path) if path else DEFAULT_CONFIG_PATH
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(self.as_dict(), f, indent=2)

    def as_dict(self) -> dict:
        return {k: getattr(self, k) for k in self.__dataclass_fields__}

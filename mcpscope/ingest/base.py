from __future__ import annotations
import json
import os
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from mcpscope.models.finding import Finding
from mcpscope.config import Settings

MAX_UPLOAD_MB = Settings.load().max_upload_mb


class ParseError(Exception):
    def __init__(self, message: str, path: str | None = None, details: str | None = None):
        self.path = path
        self.details = details
        super().__init__(message)


class BaseParser(ABC):
    SCANNER_NAME: str = "base"

    @abstractmethod
    def parse(self, data: dict) -> list[Finding]:
        ...

    def validate(self, data: Any, path: str | None = None):
        if not isinstance(data, dict):
            raise ParseError(
                f"Expected a JSON object at root, got {type(data).__name__}",
                path=path,
            )

    def load_json(self, path: str | Path) -> dict:
        path = Path(path)
        if not path.exists():
            raise ParseError(f"File not found: {path}", path=str(path))
        if path.suffix not in (".json", ".sarif"):
            raise ParseError(f"Unsupported file type: {path.suffix} (expected .json or .sarif)", path=str(path))

        size_mb = path.stat().st_size / (1024 * 1024)
        if size_mb > MAX_UPLOAD_MB:
            raise ParseError(
                f"File too large: {size_mb:.1f}MB exceeds limit of {MAX_UPLOAD_MB}MB",
                path=str(path),
            )

        try:
            with open(path) as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            raise ParseError(
                f"Invalid JSON: {e.msg} at line {e.lineno} col {e.colno}",
                path=str(path),
                details=str(e),
            )

    def parse_file(self, path: str | Path) -> list[Finding]:
        path = Path(path)
        raw = self.load_json(path)
        self.validate(raw, path=str(path))
        results = self.parse(raw)
        if not results:
            raise ParseError("No findings could be extracted", path=str(path))
        return results

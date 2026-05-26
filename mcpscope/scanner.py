from __future__ import annotations
import json
import subprocess
import tempfile
from pathlib import Path

from mcpscope.ingest.cisco_mcp import CiscoMCPParser
from mcpscope.ingest.mcpscan import MCPScanParser
from mcpscope.ingest.mcpwn import MCPwnParser
from mcpscope.models.scan import ScanRun
from mcpscope.storage.store import Store


class ScannerRunner:
    PARSERS = {
        "mcp-scan": {
            "parser": MCPScanParser(),
            "install": "pip install mcp-scan",
            "cmd": ["mcp-scan", "--json"],
        },
        "cisco-mcp": {
            "parser": CiscoMCPParser(),
            "install": "pip install cisco-ai-mcp-scanner",
            "cmd": ["mcp-scanner", "scan", "--output-format", "raw"],
        },
        "mcpwn": {
            "parser": MCPwnParser(),
            "install": "pip install mcpwn",
            "cmd": ["mcpwn", "scan", "--format", "json"],
        },
    }

    def scan(
        self, scanner_name: str, target: str, store: Store | None = None
    ) -> ScanRun:
        info = self.PARSERS.get(scanner_name)
        if not info:
            raise ValueError(
                f"Unknown scanner: {scanner_name}. Supported: {', '.join(self.PARSERS)}"
            )

        parser = info["parser"]
        cmd = info["cmd"] + [target]

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as tmp:
            tmp_path = tmp.name

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if result.returncode != 0:
                raise RuntimeError(
                    f"Scanner failed (exit {result.returncode}): {result.stderr[:500]}"
                )
            raw = json.loads(result.stdout)
        except FileNotFoundError:
            raise RuntimeError(
                f"Scanner '{scanner_name}' not found. Install it: {info['install']}"
            )
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Scanner output is not valid JSON: {e}")
        except subprocess.TimeoutExpired:
            raise RuntimeError("Scanner timed out (120s)")
        finally:
            Path(tmp_path).unlink(missing_ok=True)

        findings = parser.parse(raw)
        if not findings:
            raise RuntimeError("Scanner completed but no findings were detected")

        scan = ScanRun(
            scanner=findings[0].scanner,
            target=target,
        )
        if store:
            store.save_scan(scan, findings)
        return scan

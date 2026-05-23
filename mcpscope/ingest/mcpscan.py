from __future__ import annotations
from mcpscope.ingest.base import BaseParser, ParseError
from mcpscope.models.finding import Finding, Severity

SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "safe": Severity.INFO,
}


class MCPScanParser(BaseParser):
    SCANNER_NAME = "mcp-scan"

    def validate(self, data: dict, path: str | None = None):
        super().validate(data, path)
        if "issues" not in data and "results" not in data:
            raise ParseError(
                "Missing 'issues' or 'results' key — not an mcp-scan JSON output",
                path=path,
            )

    def parse(self, data: dict) -> list[Finding]:
        findings = []
        scanner = self.SCANNER_NAME
        target = data.get("target", data.get("config", "unknown"))

        issues = data.get("issues", data.get("results", data.get("findings", [])))
        if not isinstance(issues, list):
            raise ParseError(f"Expected 'issues' to be a list, got {type(issues).__name__}")

        servers = data.get("servers", [])
        server_map = {}
        for srv in servers:
            if isinstance(srv, dict):
                srv_name = srv.get("name", srv.get("server_name", ""))
                server_map[srv.get("id", "")] = srv_name

        for issue in issues:
            if not isinstance(issue, dict):
                continue
            code = issue.get("code", issue.get("id", ""))
            sev_raw = issue.get("severity", "info").lower()
            sev = SEVERITY_MAP.get(sev_raw, Severity.INFO)
            message = issue.get("message", issue.get("summary", issue.get("title", "")))
            description = issue.get("description", issue.get("detail", ""))
            recommendation = issue.get("recommendation", issue.get("remediation", ""))
            tool_name = issue.get("tool_name", issue.get("tool", ""))
            server_id = issue.get("server_id", issue.get("server", ""))
            server_name = issue.get("server_name", server_map.get(server_id, ""))
            if not tool_name and server_name:
                tool_name = f"server:{server_name}"

            title = f"[{code}] {message}" if code else message
            if not title:
                title = f"mcp-scan {sev_raw} finding"

            findings.append(Finding(
                scan_id=target,
                scanner=scanner,
                tool_name=tool_name or "mcp-scan",
                severity=sev,
                title=title,
                description=description or message,
                recommendation=recommendation,
                raw_data={
                    "code": code,
                    "server_name": server_name,
                    **issue,
                },
            ))

        return findings

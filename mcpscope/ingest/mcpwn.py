from __future__ import annotations
from mcpscope.ingest.base import BaseParser, ParseError
from mcpscope.models.finding import Finding, Severity

SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


class MCPwnParser(BaseParser):
    SCANNER_NAME = "mcpwn"

    def validate(self, data: dict, path: str | None = None):
        super().validate(data, path)
        if "findings" not in data and "exploits" not in data and "modules" not in data:
            raise ParseError(
                "Missing 'findings', 'exploits', or 'modules' key — not an MCPwn output",
                path=path,
            )

    def parse(self, data: dict) -> list[Finding]:
        findings = []
        scanner = self.SCANNER_NAME
        target = data.get("target", data.get("tool", data.get("card", "unknown")))

        raw_findings = data.get("findings", data.get("exploits", data.get("modules", [])))
        if not isinstance(raw_findings, list):
            raise ParseError(f"Expected findings to be a list, got {type(raw_findings).__name__}")

        for item in raw_findings:
            if not isinstance(item, dict):
                continue
            sev_raw = item.get("severity", "info").lower()
            sev = SEVERITY_MAP.get(sev_raw, Severity.INFO)
            vuln_id = item.get("id", item.get("type", ""))
            title = item.get("title", item.get("name", ""))
            test = item.get("test", item.get("module", ""))
            tool_name = item.get("tool", item.get("tool_name", ""))
            if not tool_name:
                tool_name = test or "mcpwn"
            description = item.get("description", item.get("output", item.get("detection", "")))
            recommendation = item.get("recommendation", item.get("fix", ""))
            evidence = item.get("detection", item.get("evidence", ""))

            if not title and vuln_id:
                title = f"[{vuln_id}] {test}" if test else vuln_id
            if not title and description:
                title = description[:80]

            findings.append(Finding(
                scan_id=target,
                scanner=scanner,
                tool_name=tool_name,
                severity=sev,
                title=title or "MCPwn finding",
                description=description,
                recommendation=recommendation,
                raw_data={
                    "vuln_id": vuln_id,
                    "test": test,
                    "evidence": evidence,
                    **item,
                },
            ))

        return findings

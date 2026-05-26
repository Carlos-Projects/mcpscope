from __future__ import annotations
from mcpscope.ingest.base import BaseParser, ParseError
from mcpscope.models.finding import Finding, Severity


class CiscoA2AParser(BaseParser):
    SCANNER_NAME = "cisco-a2a"

    def validate(self, data: dict, path: str | None = None):
        super().validate(data, path)
        if "findings" not in data and "results" not in data:
            raise ParseError(
                "Missing 'findings' or 'results' key — not a Cisco A2A Scanner output",
                path=path,
            )

    def parse(self, data: dict) -> list[Finding]:
        findings = []
        scanner = self.SCANNER_NAME
        target = data.get("target", data.get("card", data.get("endpoint", "unknown")))

        raw_findings = data.get(
            "findings", data.get("results", data.get("assessments", []))
        )
        if not isinstance(raw_findings, list):
            raise ParseError(
                f"Expected 'findings' to be a list, got {type(raw_findings).__name__}"
            )

        for item in raw_findings:
            if not isinstance(item, dict):
                continue
            threat_name = item.get("threat_name", "")
            sev_raw = (item.get("severity") or item.get("risk") or "info").upper()
            sev = (
                Severity.CRITICAL
                if sev_raw == "CRITICAL"
                else (
                    Severity.HIGH
                    if sev_raw == "HIGH"
                    else (
                        Severity.MEDIUM
                        if sev_raw == "MEDIUM"
                        else (Severity.LOW if sev_raw == "LOW" else Severity.INFO)
                    )
                )
            )
            analyzer = item.get("analyzer", "unknown")
            summary = item.get("summary", "")
            description = item.get("description", summary)
            aitech = item.get("aitech", "")
            aitech_name = item.get("aitech_name", "")
            aisubtech = item.get("aisubtech", "")
            aisubtech_name = item.get("aisubtech_name", "")

            location = ""
            if isinstance(item.get("details"), dict):
                location = item["details"].get("field", "")

            title = (
                threat_name or f"[{analyzer}] {summary[:60]}"
                if summary
                else f"{analyzer} finding"
            )
            if aitech:
                title = f"[{aitech}] {aitech_name}"
            if aisubtech:
                title = f"[{aisubtech}] {aisubtech_name or title}"

            findings.append(
                Finding(
                    scan_id=target,
                    scanner=scanner,
                    tool_name=f"a2a-{analyzer.lower()}",
                    severity=sev,
                    title=title,
                    description=description or summary,
                    raw_data={
                        "threat_name": threat_name,
                        "analyzer": analyzer,
                        "aitech": aitech,
                        "aitech_name": aitech_name,
                        "aisubtech": aisubtech,
                        "aisubtech_name": aisubtech_name,
                        "location": location,
                        "details": item.get("details"),
                    },
                )
            )

        return findings

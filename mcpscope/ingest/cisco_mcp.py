from __future__ import annotations
from mcpscope.ingest.base import BaseParser, ParseError
from mcpscope.models.finding import Finding, Severity

SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
    "SAFE": Severity.INFO,
    "UNKNOWN": Severity.INFO,
}

ANALYZER_DISPLAY_NAMES = {
    "api_analyzer": "API",
    "yara_analyzer": "YARA",
    "llm_analyzer": "LLM",
    "behavioral_analyzer": "Behavioral",
    "readiness_analyzer": "Readiness",
}


class CiscoMCPParser(BaseParser):
    SCANNER_NAME = "cisco-mcp"

    def validate(self, data: dict, path: str | None = None):
        super().validate(data, path)
        if "scan_results" not in data and "results" not in data:
            raise ParseError(
                "Missing 'scan_results' or 'results' key — not a Cisco MCP Scanner output",
                path=path,
            )

    def parse(self, data: dict) -> list[Finding]:
        findings = []
        scanner = self.SCANNER_NAME
        server_url = data.get("server_url", "unknown")
        scan_results = data.get("scan_results", data.get("results", [data]))

        for result in scan_results:
            tool_name = result.get("tool_name", result.get("prompt_name", result.get("resource_uri", "unknown")))
            item_type = result.get("item_type", "tool")
            status = result.get("status", "unknown")
            is_safe = result.get("is_safe", True)

            result_findings = result.get("findings", {})
            if not isinstance(result_findings, dict):
                continue

            for analyzer_key, analyzer_data in result_findings.items():
                analyzer_label = ANALYZER_DISPLAY_NAMES.get(analyzer_key, analyzer_key)
                sev_raw = analyzer_data.get("severity", "INFO").upper()
                sev = SEVERITY_MAP.get(sev_raw, Severity.INFO)

                total = analyzer_data.get("total_findings", 0)

                threat_names = analyzer_data.get("threat_names", [])
                threat_summary = analyzer_data.get("threat_summary", "")
                threats = analyzer_data.get("threats", {})

                threat_items = threats.get("items", []) if isinstance(threats, dict) else []

                if threat_items:
                    for technique in threat_items:
                        technique_id = technique.get("technique_id", "")
                        technique_name = technique.get("technique_name", "")
                        sub_items = technique.get("items", [])
                        for sub in sub_items:
                            sub_id = sub.get("sub_technique_id", "")
                            sub_name = sub.get("sub_technique_name", "")
                            max_sev = sub.get("max_severity", sev_raw)
                            desc = sub.get("description", threat_summary)

                            title = f"[{technique_id}] {technique_name}"
                            if sub_id:
                                title = f"[{sub_id}] {sub_name}"

                            findings.append(Finding(
                                scan_id=server_url,
                                scanner=scanner,
                                tool_name=tool_name,
                                severity=SEVERITY_MAP.get(max_sev.upper(), sev),
                                title=title,
                                description=desc,
                                raw_data={
                                    "analyzer": analyzer_label,
                                    "item_type": item_type,
                                    "status": status,
                                    "is_safe": is_safe,
                                    "technique": technique,
                                    "sub_technique": sub,
                                },
                            ))
                elif threat_names:
                    for threat in threat_names:
                        findings.append(Finding(
                            scan_id=server_url,
                            scanner=scanner,
                            tool_name=tool_name,
                            severity=sev,
                            title=f"[{analyzer_label}] {threat}",
                            description=threat_summary,
                            raw_data={
                                "analyzer": analyzer_label,
                                "item_type": item_type,
                                "status": status,
                                "is_safe": is_safe,
                                "threat": threat,
                            },
                        ))
                elif total > 0 and threat_summary:
                    findings.append(Finding(
                        scan_id=server_url,
                        scanner=scanner,
                        tool_name=tool_name,
                        severity=sev,
                        title=f"[{analyzer_label}] {threat_summary[:80]}",
                        description=threat_summary,
                        raw_data={
                            "analyzer": analyzer_label,
                            "item_type": item_type,
                            "status": status,
                            "is_safe": is_safe,
                        },
                    ))

        return findings

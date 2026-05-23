from __future__ import annotations
from mcpscope.ingest.base import BaseParser, ParseError
from mcpscope.models.finding import Finding, Severity

SEVERITY_MAP = {
    "error": Severity.CRITICAL,
    "warning": Severity.MEDIUM,
    "note": Severity.LOW,
    "none": Severity.INFO,
}


class SarifParser(BaseParser):
    SCANNER_NAME = "sarif"

    def validate(self, data: dict, path: str | None = None):
        super().validate(data, path)
        if "$schema" not in str(data.get("$schema", "")):
            if "version" not in data or "runs" not in data:
                raise ParseError(
                    "Missing '$schema'/'version' and 'runs' — not a SARIF file",
                    path=path,
                )

    def parse(self, data: dict) -> list[Finding]:
        findings = []
        scanner = self.SCANNER_NAME
        target = data.get("target", "sarif-report")

        runs = data.get("runs", [])
        if not isinstance(runs, list):
            raise ParseError(f"Expected 'runs' to be a list, got {type(runs).__name__}")

        for run in runs:
            tool_name = "unknown"
            if isinstance(run.get("tool"), dict):
                driver = run["tool"].get("driver", {})
                tool_name = driver.get("name", driver.get("fullName", "unknown"))
                tool_version = driver.get("version", "")

            run_results = run.get("results", [])
            if not isinstance(run_results, list):
                continue

            rules_map = {}
            if isinstance(run.get("tool"), dict):
                driver = run["tool"].get("driver", {})
                rules = driver.get("rules", [])
                if isinstance(rules, list):
                    for rule in rules:
                        rule_id = rule.get("id", "")
                        rules_map[rule_id] = {
                            "name": rule.get("name", ""),
                            "shortDescription": "",
                            "fullDescription": "",
                        }
                        if isinstance(rule.get("shortDescription"), dict):
                            rules_map[rule_id]["shortDescription"] = rule["shortDescription"].get("text", "")
                        if isinstance(rule.get("fullDescription"), dict):
                            rules_map[rule_id]["fullDescription"] = rule["fullDescription"].get("text", "")

            for result in run_results:
                if not isinstance(result, dict):
                    continue
                rule_id = result.get("ruleId", "")
                rule_info = rules_map.get(rule_id, {})

                level = result.get("level", "warning")
                sev = SEVERITY_MAP.get(level, Severity.INFO)

                message = ""
                if isinstance(result.get("message"), dict):
                    message = result["message"].get("text", "")

                title = rule_info.get("name", rule_id) or rule_id
                description = rule_info.get("fullDescription", rule_info.get("shortDescription", message))
                if not description:
                    description = message

                locations = result.get("locations", [])
                loc_str = ""
                if isinstance(locations, list) and locations:
                    phys = locations[0].get("physicalLocation", {})
                    artifact = phys.get("artifactLocation", {})
                    loc_str = artifact.get("uri", "")

                findings.append(Finding(
                    scan_id=target,
                    scanner=scanner,
                    tool_name=tool_name,
                    tool_version=tool_version,
                    severity=sev,
                    title=title,
                    description=description,
                    raw_data={
                        "rule_id": rule_id,
                        "level": level,
                        "location": loc_str,
                        **result,
                    },
                ))

        return findings

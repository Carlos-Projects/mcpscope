import pytest
import json
from pathlib import Path
from mcpscope.ingest.cisco_mcp import CiscoMCPParser
from mcpscope.ingest.cisco_a2a import CiscoA2AParser
from mcpscope.ingest.mcpscan import MCPScanParser
from mcpscope.ingest.mcpwn import MCPwnParser
from mcpscope.ingest.sarif import SarifParser
from mcpscope.ingest.base import ParseError
from mcpscope.models.finding import Severity


def load_fixture(name: str) -> dict:
    path = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / name
    with open(path) as f:
        return json.load(f)


class TestCiscoMCPParser:
    def setup_method(self):
        self.parser = CiscoMCPParser()

    def test_parse_valid(self):
        data = {
            "server_url": "https://example.com/mcp",
            "scan_results": [{
                "tool_name": "add",
                "status": "completed",
                "findings": {
                    "api_analyzer": {
                        "severity": "HIGH",
                        "total_findings": 1,
                        "threats": {
                            "items": [{
                                "technique_id": "AITech-8.2",
                                "technique_name": "Data Exfiltration",
                                "items": [{
                                    "sub_technique_id": "AISubtech-8.2.3",
                                    "sub_technique_name": "Data Exfiltration via Agent Tooling",
                                    "max_severity": "HIGH",
                                    "description": "Sensitive data may be exposed"
                                }]
                            }]
                        },
                        "threat_names": ["Data Exfiltration"],
                        "threat_summary": "Tool may expose data"
                    }
                },
                "is_safe": False
            }]
        }
        findings = self.parser.parse(data)
        assert len(findings) == 1
        assert findings[0].tool_name == "add"
        assert findings[0].severity == Severity.HIGH
        assert "AISubtech-8.2.3" in findings[0].title

    def test_parse_safe_tool(self):
        data = {
            "server_url": "https://example.com/mcp",
            "scan_results": [{
                "tool_name": "safe_tool",
                "status": "completed",
                "findings": {
                    "api_analyzer": {"severity": "SAFE", "total_findings": 0},
                    "yara_analyzer": {"severity": "SAFE", "total_findings": 0},
                },
                "is_safe": True
            }]
        }
        findings = self.parser.parse(data)
        assert len(findings) == 0

    def test_validate_rejects_bad_data(self):
        with pytest.raises(ParseError, match="Missing 'scan_results'"):
            self.parser.validate({"foo": "bar"})


class TestCiscoA2AParser:
    def setup_method(self):
        self.parser = CiscoA2AParser()

    def test_parse_valid(self):
        data = {
            "target": "https://agent.example.com",
            "findings": [{
                "threat_name": "PROMPT INJECTION",
                "severity": "HIGH",
                "analyzer": "YARA",
                "aitech": "AITech-1.1",
                "aitech_name": "Direct Prompt Injection",
                "description": "Prompt injection detected",
                "summary": "Found injection patterns"
            }]
        }
        findings = self.parser.parse(data)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert "AITech-1.1" in findings[0].title

    def test_validate_rejects_bad_data(self):
        with pytest.raises(ParseError, match="Missing 'findings'"):
            self.parser.validate({"nope": True})


class TestMCPScanParser:
    def setup_method(self):
        self.parser = MCPScanParser()

    def test_parse_valid(self):
        data = {
            "target": "mcp.json",
            "servers": [{"id": "s1", "name": "Demo Server"}],
            "issues": [{
                "code": "E001",
                "severity": "high",
                "message": "Prompt injection risk",
                "tool_name": "add",
                "description": "Tool description contains injection vectors",
                "recommendation": "Sanitize description"
            }]
        }
        findings = self.parser.parse(data)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert "E001" in findings[0].title

    def test_validate_rejects_bad_data(self):
        with pytest.raises(ParseError, match="Missing 'issues'"):
            self.parser.validate({"x": []})


class TestMCPwnParser:
    def setup_method(self):
        self.parser = MCPwnParser()

    def test_parse_new_format(self):
        data = {
            "target": "server.py",
            "findings": [{
                "id": "MCP-001",
                "severity": "CRITICAL",
                "title": "Tool Poisoning",
                "tool": "fetch_url",
                "description": "Hidden instructions found",
                "recommendation": "Audit tool descriptions"
            }]
        }
        findings = self.parser.parse(data)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].tool_name == "fetch_url"

    def test_parse_legacy_format(self):
        data = {
            "tool": "Mcpwn",
            "findings": [{
                "test": "tool_injection",
                "type": "RCE",
                "severity": "CRITICAL",
                "tool": "exec_cmd",
                "detection": "uid=1000",
                "description": "RCE via command injection"
            }]
        }
        findings = self.parser.parse(data)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_validate_rejects_bad_data(self):
        with pytest.raises(ParseError, match="Missing 'findings'"):
            self.parser.validate({"version": "1.0"})


class TestSarifParser:
    def setup_method(self):
        self.parser = SarifParser()

    def test_parse_valid(self):
        data = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "TestScanner",
                        "version": "1.0",
                        "rules": [{
                            "id": "RULE001",
                            "name": "Test Rule",
                            "shortDescription": {"text": "A test rule"},
                            "fullDescription": {"text": "Full description of test rule"}
                        }]
                    }
                },
                "results": [{
                    "ruleId": "RULE001",
                    "level": "error",
                    "message": {"text": "Vulnerability found"}
                }]
            }]
        }
        findings = self.parser.parse(data)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].tool_name == "TestScanner"

    def test_validate_rejects_bad_data(self):
        with pytest.raises(ParseError, match="Missing"):
            self.parser.validate({"foo": "bar"})


class TestStore:
    def test_save_and_retrieve(self):
        from mcpscope.storage.store import Store
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        store = Store(db_path=db_path)
        from mcpscope.models.finding import Finding
        from mcpscope.models.scan import ScanRun
        scan = ScanRun(id="test-scan", scanner="test", target="test-target")
        findings = [
            Finding(scan_id="test-scan", scanner="test", tool_name="tool1",
                    severity=Severity.CRITICAL, title="Critical finding"),
            Finding(scan_id="test-scan", scanner="test", tool_name="tool2",
                    severity=Severity.LOW, title="Low finding"),
        ]
        saved = store.save_scan(scan, findings)
        assert saved.id == "test-scan"
        assert saved.critical_count == 1
        assert saved.low_count == 1
        retrieved, total = store.get_findings(scan_id="test-scan")
        assert total == 2
        titles = {f.title for f in retrieved}
        assert "Critical finding" in titles
        assert "Low finding" in titles
        import os
        os.unlink(db_path)


class TestCLI:
    def test_import_unknown_scanner(self):
        from mcpscope.cli import PARSERS
        assert "cisco-mcp" in PARSERS
        assert "cisco-a2a" in PARSERS
        assert "mcp-scan" in PARSERS
        assert "mcpscan" in PARSERS
        assert "mcpwn" in PARSERS
        assert "sarif" in PARSERS


class TestConfig:
    def test_defaults(self):
        from mcpscope.config import Settings
        s = Settings()
        assert s.port == 8080
        assert s.host == "127.0.0.1"
        assert s.auto_refresh_seconds == 30
        assert s.api_key is None
        assert s.webhook_urls == []
        assert s.max_upload_mb == 50

    def test_save_load_roundtrip(self):
        from mcpscope.config import Settings
        import tempfile, os, json
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            path = f.name
            json.dump({"port": 9090, "host": "0.0.0.0", "auto_refresh_seconds": 60}, f)
        s = Settings.load(path)
        assert s.port == 9090
        assert s.host == "0.0.0.0"
        assert s.auto_refresh_seconds == 60
        os.unlink(path)


class TestDedup:
    def test_duplicates(self):
        import tempfile, os
        from mcpscope.storage.store import Store
        from mcpscope.models.finding import Finding
        from mcpscope.models.scan import ScanRun
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        store = Store(db_path=db_path)
        scan1 = ScanRun(id="s1", scanner="test", target="t1")
        store.save_scan(scan1, [
            Finding(scan_id="s1", scanner="test", tool_name="foo", severity=Severity.CRITICAL, title="Same issue"),
            Finding(scan_id="s1", scanner="test", tool_name="bar", severity=Severity.LOW, title="Unique"),
        ])
        scan2 = ScanRun(id="s2", scanner="test", target="t2")
        store.save_scan(scan2, [
            Finding(scan_id="s2", scanner="test", tool_name="foo", severity=Severity.CRITICAL, title="Same issue"),
            Finding(scan_id="s2", scanner="test", tool_name="baz", severity=Severity.HIGH, title="Another"),
        ])
        dups = store.get_duplicates()
        assert len(dups) >= 1
        dup = [d for d in dups if d["tool_name"] == "foo"][0]
        assert dup["count"] == 2
        os.unlink(db_path)


class TestScanDiff:
    def test_diff(self):
        import tempfile, os
        from mcpscope.storage.store import Store
        from mcpscope.models.finding import Finding
        from mcpscope.models.scan import ScanRun
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        store = Store(db_path=db_path)
        store.save_scan(ScanRun(id="a", scanner="t", target="t1"), [
            Finding(scan_id="a", scanner="t", tool_name="x", severity=Severity.CRITICAL, title="Only in A"),
            Finding(scan_id="a", scanner="t", tool_name="y", severity=Severity.HIGH, title="Both"),
        ])
        store.save_scan(ScanRun(id="b", scanner="t", target="t2"), [
            Finding(scan_id="b", scanner="t", tool_name="y", severity=Severity.HIGH, title="Both"),
            Finding(scan_id="b", scanner="t", tool_name="z", severity=Severity.MEDIUM, title="Only in B"),
        ])
        diff = store.diff_scans("a", "b")
        assert diff["new_count"] == 1
        assert diff["fixed_count"] == 1
        assert diff["unchanged_count"] == 1
        os.unlink(db_path)


class TestWebhookPayload:
    def test_notify_skips_safe(self):
        from mcpscope.webhooks import notify_scan_imported
        from mcpscope.models.finding import Finding, Severity
        findings = [Finding(scan_id="x", scanner="t", tool_name="t", severity=Severity.INFO, title="safe")]
        notify_scan_imported([], findings=findings, findings_count=1, critical_count=0, high_count=0)

    def test_notify_builds_alerts(self):
        from mcpscope.webhooks import notify_scan_imported
        from mcpscope.models.finding import Finding, Severity
        findings = [
            Finding(scan_id="x", scanner="t", tool_name="t1", severity=Severity.CRITICAL, title="bad"),
            Finding(scan_id="x", scanner="t", tool_name="t2", severity=Severity.HIGH, title="warn"),
        ]
        notify_scan_imported(["http://localhost:9999/noexist"], findings=findings,
                             findings_count=2, critical_count=1, high_count=1)


class TestFileSizeValidation:
    def test_large_file_rejected(self):
        import mcpscope.ingest.base as base_mod
        from mcpscope.ingest.mcpscan import MCPScanParser
        from mcpscope.ingest.base import ParseError
        import tempfile, os
        orig_max = base_mod.MAX_UPLOAD_MB
        base_mod.MAX_UPLOAD_MB = 1
        try:
            parser = MCPScanParser()
            with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
                f.write('{"issues": []}')
                path = f.name
            os.truncate(path, 2 * 1024 * 1024 + 1)
            with pytest.raises(ParseError, match="too large"):
                parser.parse_file(path)
        finally:
            base_mod.MAX_UPLOAD_MB = orig_max
            os.unlink(path)


class TestCSVReport:
    def test_csv_format(self):
        from mcpscope.storage.store import Store
        from mcpscope.models.finding import Finding, Severity
        from mcpscope.models.scan import ScanRun
        import tempfile, os, csv, io
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        store = Store(db_path=db_path)
        store.save_scan(ScanRun(id="csv-test", scanner="t", target="t"), [
            Finding(scan_id="csv-test", scanner="t", tool_name="x", severity=Severity.CRITICAL, title="CSV finding"),
        ])
        findings, _ = store.get_findings(page_size=1000)
        output = io.StringIO()
        w = csv.writer(output)
        w.writerow(["id", "severity", "title"])
        for f in findings:
            sev = f.severity.value if hasattr(f.severity, 'value') else f.severity
            w.writerow([f.id, sev, f.title])
        result = output.getvalue()
        assert "CSV finding" in result
        assert "critical" in result
        os.unlink(db_path)

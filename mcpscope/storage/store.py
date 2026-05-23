from __future__ import annotations
import sqlite3
import uuid
import json
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from mcpscope.models.finding import Finding, Severity, SEVERITY_ORDER
from mcpscope.models.scan import ScanRun, ScanHistory
from mcpscope.config import Settings

DEFAULT_DB = Path.home() / ".mcpscope" / "mcpscope.db"
PAGE_SIZE = 50


class Store:
    def __init__(self, db_path: str | Path = DEFAULT_DB):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_db()
        self._webhooks = Settings.load().webhook_urls

    def _init_db(self):
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS scan_runs (
                id TEXT PRIMARY KEY,
                scanner TEXT NOT NULL,
                target TEXT,
                findings_count INTEGER DEFAULT 0,
                critical_count INTEGER DEFAULT 0,
                high_count INTEGER DEFAULT 0,
                medium_count INTEGER DEFAULT 0,
                low_count INTEGER DEFAULT 0,
                info_count INTEGER DEFAULT 0,
                raw_file TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                scan_id TEXT NOT NULL,
                scanner TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                tool_version TEXT,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                recommendation TEXT,
                cvss_score REAL,
                cve_id TEXT,
                raw_data TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scan_runs(id)
            );
            CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
            CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
            CREATE INDEX IF NOT EXISTS idx_findings_tool ON findings(tool_name);
            CREATE INDEX IF NOT EXISTS idx_findings_created ON findings(created_at);
            CREATE INDEX IF NOT EXISTS idx_findings_title ON findings(title);
        """)

    def save_scan(self, scan: ScanRun, findings: list[Finding]) -> ScanRun:
        scan.id = scan.id or str(uuid.uuid4())
        scan.created_at = scan.created_at or datetime.now(timezone.utc).isoformat()

        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            f.id = f.id or str(uuid.uuid4())
            f.scan_id = scan.id
            sev = f.severity.value if isinstance(f.severity, Severity) else f.severity
            if sev in counts:
                counts[sev] += 1

        scan.findings_count = len(findings)
        scan.critical_count = counts["critical"]
        scan.high_count = counts["high"]
        scan.medium_count = counts["medium"]
        scan.low_count = counts["low"]
        scan.info_count = counts["info"]

        with self._conn:
            self._conn.execute(
                """INSERT OR REPLACE INTO scan_runs
                   (id, scanner, target, findings_count, critical_count, high_count,
                    medium_count, low_count, info_count, raw_file, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (scan.id, scan.scanner, scan.target, scan.findings_count,
                 scan.critical_count, scan.high_count, scan.medium_count,
                 scan.low_count, scan.info_count, scan.raw_file, scan.created_at),
            )
            for f in findings:
                self._conn.execute(
                    """INSERT OR REPLACE INTO findings
                       (id, scan_id, scanner, tool_name, tool_version, severity,
                        title, description, recommendation, cvss_score, cve_id, raw_data, created_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (f.id, f.scan_id, f.scanner, f.tool_name, f.tool_version,
                     f.severity.value if isinstance(f.severity, Severity) else f.severity,
                     f.title, f.description, f.recommendation,
                     f.cvss_score, f.cve_id,
                     json.dumps(f.raw_data) if f.raw_data else None,
                     f.created_at),
                )

        cfg = Settings.load()
        if self._webhooks or cfg.slack_webhook_url:
            from mcpscope.webhooks import notify_scan_imported
            notify_scan_imported(
                self._webhooks,
                findings=findings,
                findings_count=scan.findings_count,
                critical_count=scan.critical_count,
                high_count=scan.high_count,
                scan_id=scan.id,
                scanner=scan.scanner,
                slack_url=cfg.slack_webhook_url or "",
            )

        return scan

    def get_all_scans(self) -> list[ScanRun]:
        rows = self._conn.execute("SELECT * FROM scan_runs ORDER BY created_at DESC").fetchall()
        return [ScanRun(**dict(r)) for r in rows]

    def get_scans_paginated(self, page: int = 1, page_size: int = PAGE_SIZE) -> tuple[list[ScanRun], int]:
        offset = (page - 1) * page_size
        count_row = self._conn.execute("SELECT COUNT(*) as c FROM scan_runs").fetchone()
        total = count_row["c"] if count_row else 0
        rows = self._conn.execute(
            "SELECT * FROM scan_runs ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (page_size, offset),
        ).fetchall()
        return [ScanRun(**dict(r)) for r in rows], total

    def get_scan(self, scan_id: str) -> ScanRun | None:
        row = self._conn.execute("SELECT * FROM scan_runs WHERE id = ?", (scan_id,)).fetchone()
        return ScanRun(**dict(row)) if row else None

    def get_findings(self, scan_id: str | None = None, severity: str | None = None,
                     tool_name: str | None = None, scanner: str | None = None,
                     search: str | None = None,
                     page: int = 1, page_size: int = PAGE_SIZE) -> tuple[list[Finding], int]:
        query = "SELECT * FROM findings WHERE 1=1"
        count_query = "SELECT COUNT(*) as c FROM findings WHERE 1=1"
        params = []
        if scan_id:
            query += " AND scan_id = ?"
            count_query += " AND scan_id = ?"
            params.append(scan_id)
        if severity:
            query += " AND severity = ?"
            count_query += " AND severity = ?"
            params.append(severity)
        if tool_name:
            query += " AND tool_name = ?"
            count_query += " AND tool_name = ?"
            params.append(tool_name)
        if scanner:
            query += " AND scanner = ?"
            count_query += " AND scanner = ?"
            params.append(scanner)
        if search:
            query += " AND (title LIKE ? OR description LIKE ? OR tool_name LIKE ?)"
            count_query += " AND (title LIKE ? OR description LIKE ? OR tool_name LIKE ?)"
            like = f"%{search}%"
            params.extend([like, like, like])

        count_row = self._conn.execute(count_query, params).fetchone()
        total = count_row["c"] if count_row else 0

        offset = (page - 1) * page_size
        query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        rows = self._conn.execute(query, params + [page_size, offset]).fetchall()

        result = []
        for r in rows:
            d = dict(r)
            if d.get("raw_data"):
                try:
                    d["raw_data"] = json.loads(d["raw_data"])
                except (json.JSONDecodeError, TypeError):
                    pass
            result.append(Finding(**d))
        return result, total

    def get_finding(self, finding_id: str) -> Finding | None:
        row = self._conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        if d.get("raw_data"):
            try:
                d["raw_data"] = json.loads(d["raw_data"])
            except (json.JSONDecodeError, TypeError):
                pass
        return Finding(**d)

    def get_scan_history(self) -> ScanHistory:
        scans = self.get_all_scans()
        history = ScanHistory(scans=scans)
        for s in scans:
            history.total_findings += s.findings_count
            history.total_critical += s.critical_count
            history.total_high += s.high_count
            history.total_medium += s.medium_count
            history.total_low += s.low_count
            history.total_info += s.info_count
        return history

    def get_top_tools(self, limit: int = 10) -> list[dict]:
        rows = self._conn.execute(
            """SELECT tool_name, COUNT(*) as total,
                      SUM(CASE WHEN severity IN ('critical','high') THEN 1 ELSE 0 END) as critical_high
               FROM findings GROUP BY tool_name ORDER BY critical_high DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_severity_trend(self) -> list[dict]:
        rows = self._conn.execute(
            """SELECT DATE(created_at) as date, severity, COUNT(*) as count
               FROM findings
               GROUP BY DATE(created_at), severity
               ORDER BY date ASC""",
        ).fetchall()
        return [dict(r) for r in rows]

    def get_scanners(self) -> list[str]:
        rows = self._conn.execute(
            "SELECT DISTINCT scanner FROM scan_runs ORDER BY scanner"
        ).fetchall()
        return [r["scanner"] for r in rows]

    def get_tool_names(self) -> list[str]:
        rows = self._conn.execute(
            "SELECT DISTINCT tool_name FROM findings ORDER BY tool_name"
        ).fetchall()
        return [r["tool_name"] for r in rows]

    def get_duplicates(self, threshold: float = 0.8) -> list[dict]:
        rows = self._conn.execute(
            """SELECT tool_name, title, severity, scanner,
                      COUNT(*) as count,
                      GROUP_CONCAT(id) as finding_ids,
                      GROUP_CONCAT(scan_id) as scan_ids,
                      GROUP_CONCAT(created_at) as created_ats
               FROM findings
               GROUP BY tool_name, title, severity
               HAVING COUNT(*) > 1
               ORDER BY COUNT(*) DESC"""
        ).fetchall()
        return [dict(r) for r in rows]

    def diff_scans(self, scan_a: str, scan_b: str) -> dict:
        sa = self.get_scan(scan_a)
        sb = self.get_scan(scan_b)
        if not sa or not sb:
            raise ValueError("One or both scans not found")

        fa_list = self.get_findings(scan_id=scan_a, page_size=10000)[0]
        fb_list = self.get_findings(scan_id=scan_b, page_size=10000)[0]

        key_a = {(f.tool_name, f.title, f.severity.value if isinstance(f.severity, Severity) else f.severity) for f in fa_list}
        key_b = {(f.tool_name, f.title, f.severity.value if isinstance(f.severity, Severity) else f.severity) for f in fb_list}

        new_in_b = [f.model_dump() for f in fb_list if (f.tool_name, f.title, f.severity.value if isinstance(f.severity, Severity) else f.severity) not in key_a]
        fixed_in_b = [f.model_dump() for f in fa_list if (f.tool_name, f.title, f.severity.value if isinstance(f.severity, Severity) else f.severity) not in key_b]

        return {
            "scan_a": {"id": scan_a, "scanner": sa.scanner, "target": sa.target, "findings_count": sa.findings_count},
            "scan_b": {"id": scan_b, "scanner": sb.scanner, "target": sb.target, "findings_count": sb.findings_count},
            "new_findings": new_in_b,
            "fixed_findings": fixed_in_b,
            "new_count": len(new_in_b),
            "fixed_count": len(fixed_in_b),
            "unchanged_count": len(fb_list) - len(new_in_b),
        }

    def clear(self):
        with self._conn:
            self._conn.execute("DELETE FROM findings")
            self._conn.execute("DELETE FROM scan_runs")

    def backup(self, path: str | Path):
        path = Path(path)
        self._conn.commit()
        shutil.copy2(self.db_path, path)

    def restore(self, path: str | Path):
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Backup not found: {path}")
        self._conn.close()
        shutil.copy2(path, self.db_path)
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row

    def prune(self, keep_days: int = 30) -> int:
        from datetime import datetime, timedelta, timezone
        cutoff = (datetime.now(timezone.utc) - timedelta(days=keep_days)).isoformat()
        with self._conn:
            cur = self._conn.execute("DELETE FROM findings WHERE scan_id IN (SELECT id FROM scan_runs WHERE created_at < ?)", (cutoff,))
            deleted_findings = cur.rowcount
            cur = self._conn.execute("DELETE FROM scan_runs WHERE created_at < ?", (cutoff,))
            deleted_scans = cur.rowcount
        return deleted_scans

    def seed_demo_data(self):
        import random
        scanners_demo = ["cisco-mcp", "cisco-a2a", "mcp-scan", "mcpwn"]
        tools_pool = [
            ("execute_command", "critical"),
            ("read_file", "high"),
            ("fetch_url", "critical"),
            ("search_db", "medium"),
            ("write_file", "high"),
            ("list_dir", "low"),
            ("send_email", "medium"),
            ("run_shell", "critical"),
            ("parse_xml", "low"),
            ("make_request", "high"),
        ]
        now = datetime.now(timezone.utc)
        for i in range(6):
            scanner = random.choice(scanners_demo)
            scan_id = f"demo-scan-{i+1}"
            target = f"demo-server-{i % 3 + 1}.local"
            created = (now - timedelta(hours=i * 12)).isoformat()
            count = random.randint(2, 6)
            selected = random.sample(tools_pool, min(count, len(tools_pool)))
            findings = []
            for tool_name, sev_str in selected:
                sev = Severity(sev_str)
                findings.append(Finding(
                    scan_id=scan_id,
                    scanner=scanner,
                    tool_name=tool_name,
                    severity=sev,
                    title=f"{sev.name.title()}: {tool_name.replace('_', ' ').title()}",
                    description=f"Security issue detected in {tool_name}",
                    recommendation=f"Review and fix {tool_name} configuration",
                    created_at=created,
                ))
            scan = ScanRun(
                id=scan_id,
                scanner=scanner,
                target=target,
                created_at=created,
            )
            self.save_scan(scan, findings)

from __future__ import annotations
import sys
import json
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich.progress import Progress

from mcpscope.api.server import create_app
from mcpscope.storage.store import Store
from mcpscope.ingest.cisco_mcp import CiscoMCPParser
from mcpscope.ingest.cisco_a2a import CiscoA2AParser
from mcpscope.ingest.mcpscan import MCPScanParser
from mcpscope.ingest.mcpwn import MCPwnParser
from mcpscope.ingest.sarif import SarifParser
from mcpscope.ingest.base import ParseError
from mcpscope.models.scan import ScanRun
from mcpscope.config import Settings
from mcpscope.scanner import ScannerRunner

console = Console()
PARSERS = {
    "cisco-mcp": CiscoMCPParser(),
    "cisco-a2a": CiscoA2AParser(),
    "mcp-scan": MCPScanParser(),
    "mcpscan": MCPScanParser(),
    "mcpwn": MCPwnParser(),
    "sarif": SarifParser(),
}


def cmd_import(args: list[str]):
    if len(args) < 2:
        console.print("[red]Usage: mcpscope import <scanner> <file> [target][/red]")
        sys.exit(1)

    scanner_name = args[0].lower()
    file_path = Path(args[1])
    target = args[2] if len(args) > 2 else None

    parser = PARSERS.get(scanner_name)
    if not parser:
        console.print(f"[red]Unknown scanner: {scanner_name}. Available: {', '.join(PARSERS)}[/red]")
        sys.exit(1)

    if not file_path.exists():
        console.print(f"[red]File not found: {file_path}[/red]")
        sys.exit(1)

    store = Store()

    try:
        with Progress() as progress:
            task = progress.add_task(f"Parsing {file_path.name}...", total=None)
            findings = parser.parse_file(file_path)
            progress.update(task, completed=True)
    except ParseError as e:
        console.print(f"[red]Parse error: {e}[/red]")
        if e.details:
            console.print(f"[dim]{e.details}[/dim]")
        sys.exit(1)

    scanner_label = findings[0].scanner
    scan = ScanRun(
        id=file_path.stem,
        scanner=scanner_label,
        target=target or scanner_label,
        raw_file=str(file_path.resolve()),
    )
    saved = store.save_scan(scan, findings)

    table = Table(title=f"Imported: {file_path.name}")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    table.add_row("Scanner", scanner_label)
    table.add_row("Findings", str(len(findings)))
    table.add_row("Critical", str(saved.critical_count))
    table.add_row("High", str(saved.high_count))
    table.add_row("Medium", str(saved.medium_count))
    table.add_row("Low", str(saved.low_count))
    table.add_row("Info", str(saved.info_count))
    table.add_row("Scan ID", saved.id)
    console.print(table)


def cmd_serve(args: list[str]):
    settings = Settings.load()
    for i, a in enumerate(args):
        if a == "--port" and i + 1 < len(args):
            settings.port = int(args[i + 1])
        elif a == "--host" and i + 1 < len(args):
            settings.host = args[i + 1]
        elif a == "--config" and i + 1 < len(args):
            settings = Settings.load(args[i + 1])

    import uvicorn
    store = Store(db_path=settings.db_path)
    app = create_app(store)
    app.state.auto_refresh = settings.auto_refresh_seconds
    console.print(f"[green]MCP-Scope dashboard running at http://{settings.host}:{settings.port}[/green]")
    console.print(f"[dim]DB: {settings.db_path} | Auto-refresh: {settings.auto_refresh_seconds}s[/dim]")
    uvicorn.run(app, host=settings.host, port=settings.port, log_level=settings.log_level)


def cmd_report(args: list[str]):
    fmt = "json"
    output = "mcpscope-report.json"
    for i, a in enumerate(args):
        if a == "--format" and i + 1 < len(args):
            fmt = args[i + 1].lower()
        elif a == "--output" and i + 1 < len(args):
            output = args[i + 1]

    store = Store()
    history = store.get_scan_history()
    top = store.get_top_tools()

    report_data = {
        "generated_at": __import__("datetime").datetime.utcnow().isoformat(),
        "summary": {
            "total_scans": len(history.scans),
            "total_findings": history.total_findings,
            "critical": history.total_critical,
            "high": history.total_high,
            "medium": history.total_medium,
            "low": history.total_low,
            "info": history.total_info,
        },
        "scans": [s.model_dump() for s in history.scans],
        "top_tools": top,
    }

    out_path = Path(output)
    if fmt == "json":
        with open(out_path, "w") as f:
            json.dump(report_data, f, indent=2)
        console.print(f"[green]Report written to {out_path.resolve()}[/green]")

    elif fmt == "csv":
        import csv
        store = Store()
        findings, _ = store.get_findings(page_size=100000)
        with open(out_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["id", "scan_id", "scanner", "tool_name", "severity",
                             "title", "description", "recommendation", "created_at"])
            for finding in findings:
                sev = finding.severity.value if hasattr(finding.severity, 'value') else finding.severity
                writer.writerow([finding.id, finding.scan_id, finding.scanner,
                                 finding.tool_name, sev, finding.title,
                                 (finding.description or "")[:200],
                                 (finding.recommendation or "")[:200],
                                 finding.created_at])
        console.print(f"[green]CSV report written to {out_path.resolve()}[/green]")

    elif fmt == "pdf":
        try:
            from weasyprint import HTML
        except ImportError:
            console.print("[red]PDF generation requires: pip install mcpscope[pdf][/red]")
            sys.exit(1)

        html_content = _render_report_html(report_data)
        HTML(string=html_content).write_pdf(str(out_path))
        console.print(f"[green]PDF report written to {out_path.resolve()}[/green]")

    else:
        console.print(f"[red]Unsupported format: {fmt}. Use json, csv, or pdf.[/red]")
        sys.exit(1)


def cmd_seed(args: list[str]):
    store = Store()
    store.seed_demo_data()
    history = store.get_scan_history()
    console.print(f"[green]Seeded {len(history.scans)} demo scans with {history.total_findings} findings[/green]")


def cmd_backup(args: list[str]):
    output = args[0] if args else f"mcpscope-backup-{__import__('datetime').datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
    store = Store()
    store.backup(output)
    console.print(f"[green]Backup saved to {Path(output).resolve()}[/green]")


def cmd_restore(args: list[str]):
    if not args:
        console.print("[red]Usage: mcpscope restore <backup-file>[/red]")
        sys.exit(1)
    path = Path(args[0])
    if not path.exists():
        console.print(f"[red]Backup not found: {path}[/red]")
        sys.exit(1)
    store = Store()
    store.restore(path)
    history = store.get_scan_history()
    console.print(f"[green]Restored {len(history.scans)} scans, {history.total_findings} findings[/green]")


def cmd_config(args: list[str]):
    settings = Settings.load()
    if not args:
        console.print("[bold]Current configuration:[/bold]")
        for k, v in settings.as_dict().items():
            console.print(f"  {k}: {v}")
        console.print(f"\nConfig file: {Path.home() / '.mcpscope' / 'config.json'}")
        return

    action = args[0]
    if action == "show":
        for k, v in settings.as_dict().items():
            console.print(f"  {k}: {v}")
    elif action == "set" and len(args) >= 3:
        key, value = args[1], args[2]
        if hasattr(settings, key):
            current = getattr(settings, key)
            if value.lower() in ("none", "null", ""):
                setattr(settings, key, None)
            elif isinstance(current, bool):
                setattr(settings, key, value.lower() in ("true", "1", "yes"))
            elif isinstance(current, int):
                setattr(settings, key, int(value))
            elif isinstance(current, list):
                import json
                try:
                    setattr(settings, key, json.loads(value))
                except (json.JSONDecodeError, TypeError):
                    console.print(f"[red]Expected JSON array for {key}[/red]")
                    sys.exit(1)
            else:
                setattr(settings, key, value)
            settings.save()
            console.print(f"[green]{key} set to {value}[/green]")
        else:
            console.print(f"[red]Unknown config key: {key}[/red]")
            sys.exit(1)
    else:
        console.print("Usage: mcpscope config [show|set <key> <value>]")


def cmd_scan(args: list[str]):
    if len(args) < 2:
        console.print("[red]Usage: mcpscope scan <scanner> <target>[/red]")
        console.print(f"Scanners: {', '.join(ScannerRunner.PARSERS)}")
        sys.exit(1)

    scanner_name = args[0].lower()
    target = args[1]
    runner = ScannerRunner()
    store = Store()

    try:
        with Progress() as progress:
            task = progress.add_task(f"Running {scanner_name} against {target}...", total=None)
            scan = runner.scan(scanner_name, target, store=store)
            progress.update(task, completed=True)
    except (ValueError, RuntimeError) as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(1)

    table = Table(title=f"Scan: {scan.id[:12]}")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    table.add_row("Scanner", scan.scanner)
    table.add_row("Target", target)
    table.add_row("Findings", str(scan.findings_count))
    table.add_row("Critical", str(scan.critical_count))
    table.add_row("High", str(scan.high_count))
    table.add_row("Medium", str(scan.medium_count))
    table.add_row("Low", str(scan.low_count))
    table.add_row("Info", str(scan.info_count))
    table.add_row("Scan ID", scan.id)
    console.print(table)


def cmd_prune(args: list[str]):
    keep_days = 30
    for i, a in enumerate(args):
        if a == "--keep" and i + 1 < len(args):
            keep_days = int(args[i + 1])

    store = Store()
    count = store.prune(keep_days)
    if count:
        console.print(f"[green]Pruned {count} scans older than {keep_days} days[/green]")
    else:
        console.print(f"[yellow]No scans older than {keep_days} days to prune[/yellow]")


def _render_report_html(data: dict) -> str:
    summary = data["summary"]
    scans_rows = ""
    for s in data["scans"]:
        scans_rows += f"""<tr>
            <td>{s['id']}</td>
            <td>{s['scanner']}</td>
            <td>{s['findings_count']}</td>
            <td>{s['critical_count']}</td>
            <td>{s['high_count']}</td>
            <td>{s['medium_count']}</td>
            <td>{s['low_count']}</td>
            <td>{s['info_count']}</td>
            <td>{s['created_at']}</td>
        </tr>"""

    tools_rows = ""
    for t in data.get("top_tools", []):
        tools_rows += f"""<tr>
            <td>{t['tool_name']}</td>
            <td>{t['total']}</td>
            <td>{t['critical_high']}</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>MCP-Scope Report</title>
<style>
body {{ font-family: Helvetica, Arial, sans-serif; margin: 40px; }}
h1 {{ color: #1e293b; }}
h2 {{ color: #334155; margin-top: 30px; }}
table {{ width: 100%; border-collapse: collapse; margin: 10px 0 30px 0; }}
th, td {{ border: 1px solid #cbd5e1; padding: 8px 12px; text-align: left; }}
th {{ background: #f1f5f9; }}
.summary-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; }}
.card {{ border: 1px solid #e2e8f0; border-radius: 8px; padding: 15px; }}
.card h3 {{ margin: 0 0 5px 0; color: #64748b; font-size: 14px; }}
.card .value {{ font-size: 28px; font-weight: bold; color: #0f172a; }}
</style></head><body>
<h1>MCP-Scope Security Report</h1>
<p>Generated: {data['generated_at']}</p>
<h2>Summary</h2>
<div class="summary-grid">
    <div class="card"><h3>Total Scans</h3><div class="value">{summary['total_scans']}</div></div>
    <div class="card"><h3>Total Findings</h3><div class="value">{summary['total_findings']}</div></div>
    <div class="card"><h3>Critical</h3><div class="value">{summary['critical']}</div></div>
    <div class="card"><h3>High</h3><div class="value">{summary['high']}</div></div>
    <div class="card"><h3>Medium</h3><div class="value">{summary['medium']}</div></div>
    <div class="card"><h3>Low</h3><div class="value">{summary['low']}</div></div>
</div>
<h2>Scan History</h2>
<table><thead><tr><th>ID</th><th>Scanner</th><th>Total</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Info</th><th>Date</th></tr></thead>
<tbody>{scans_rows}</tbody></table>
<h2>Top Vulnerable Tools</h2>
<table><thead><tr><th>Tool</th><th>Total Findings</th><th>Critical/High</th></tr></thead>
<tbody>{tools_rows}</tbody></table>
</body></html>"""


def cli():
    if len(sys.argv) < 2:
        console.print("[bold]MCP-Scope[/bold] - Unified Security Dashboard")
        console.print("Usage:")
        console.print("  mcpscope serve [--port PORT] [--host HOST] [--config FILE]")
        console.print("  mcpscope scan <scanner> <target>")
        console.print("  mcpscope import <scanner> <file> [target]")
        console.print("  mcpscope report [--format json|csv|pdf] [--output FILE]")
        console.print("  mcpscope seed")
        console.print("  mcpscope prune [--keep DAYS]")
        console.print("  mcpscope backup [file]")
        console.print("  mcpscope restore <file>")
        console.print("  mcpscope config [show|set <key> <value>]")
        console.print("\nScanners (import): " + ", ".join(PARSERS))
        console.print("Scanners (scan): " + ", ".join(ScannerRunner.PARSERS))
        return

    command = sys.argv[1]
    args = sys.argv[2:]

    commands = {
        "serve": cmd_serve,
        "scan": cmd_scan,
        "import": cmd_import,
        "report": cmd_report,
        "seed": cmd_seed,
        "prune": cmd_prune,
        "backup": cmd_backup,
        "restore": cmd_restore,
        "config": cmd_config,
    }

    fn = commands.get(command)
    if fn:
        fn(args)
    else:
        console.print(f"[red]Unknown command: {command}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    cli()

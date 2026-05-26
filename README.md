<div align="center">

# MCP-Scope

**Unified security dashboard for MCP/A2A scanner results**

[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://python.org)
[![Tests](https://img.shields.io/github/actions/workflow/status/Carlos-Projects/mcpscope/scan.yml?label=tests)](https://github.com/Carlos-Projects/mcpscope/actions)
[![License](https://img.shields.io/github/license/Carlos-Projects/mcpscope)](LICENSE)
[![GitHub release](https://img.shields.io/github/v/release/Carlos-Projects/mcpscope)](https://github.com/Carlos-Projects/mcpscope/releases)
[![Code style](https://img.shields.io/badge/code%20style-ruff-261230)](https://docs.astral.sh/ruff)

---

</div>

Consumes output from multiple MCP/A2A security scanners (Cisco MCP Scanner, Cisco A2A Scanner, mcp-scan, MCPwn, SARIF) and presents a consolidated view of your security posture via a web dashboard, REST API, and CLI.

## Quick Start

```bash
pip install -e .

# Generate demo data and explore
mcpscope seed
mcpscope serve

# Run a scan directly against a server
mcpscope scan mcp-scan https://mcp-server.example.com/mcp

# Import results from different scanners
mcpscope import cisco-mcp results.json
mcpscope import cisco-a2a results.json
mcpscope import mcpwn results.json
mcpscope import sarif report.sarif

# Export a compliance report
mcpscope report --format csv --output report.csv

# Backup/Restore
mcpscope backup backup.db
mcpscope restore backup.db
```

## Commands

| Command | Description |
|---------|-------------|
| `serve` | Start the FastAPI web dashboard |
| `scan` | Run a scanner directly against a target |
| `import` | Import scanner JSON/SARIF results into SQLite |
| `report` | Export JSON, CSV, or PDF compliance report |
| `seed` | Generate demo scan data |
| `prune` | Delete scans older than N days |
| `backup` | Backup the SQLite database |
| `restore` | Restore the SQLite database from backup |
| `config` | View or set configuration options |

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /` | Dashboard UI with filters and tabs |
| `GET /findings/{id}` | Finding detail page |
| `GET /docs` | Swagger UI |
| `GET /api/health` | Health check |
| `GET /api/scans` | List scans (paginated) |
| `GET /api/scans/{id}` | Scan details with findings |
| `GET /api/scans/{a}/diff/{b}` | Compare two scans |
| `GET /api/findings` | Query findings (paginated, filterable) |
| `GET /api/findings/{id}` | Single finding |
| `GET /api/stats/summary` | Aggregated statistics |
| `GET /api/stats/top-tools` | Most vulnerable tools |
| `GET /api/stats/severity-trend` | Findings over time |
| `GET /api/stats/duplicates` | Deduplicated findings |
| `GET /api/report/json` | Full JSON report |
| `GET /api/report/csv` | CSV export |

## API Usage Examples

```bash
# Health check
curl http://localhost:8080/api/health

# List scans (paginated)
curl "http://localhost:8080/api/scans?page=1&page_size=10"

# Get scan with findings
curl http://localhost:8080/api/scans/scan-id-here

# Query findings with filters
curl "http://localhost:8080/api/findings?severity=critical&page=1"

# Search findings
curl "http://localhost:8080/api/findings?search=command"

# Compare two scans
curl "http://localhost:8080/api/scans/scan-a/diff/scan-b"

# Get stats summary
curl http://localhost:8080/api/stats/summary

# Get duplicates
curl http://localhost:8080/api/stats/duplicates

# Export as CSV
curl http://localhost:8080/api/report/csv -o report.csv

# Full JSON report
curl http://localhost:8080/api/report/json

# With API key authentication
curl -H "X-API-Key: your-key" http://localhost:8080/api/scans

# Swagger docs
open http://localhost:8080/docs
```

## Dashboard Features

- **Overview tab** — Severity pie chart, top tools bar chart, severity trend over time
- **Findings tab** — Filterable table with severity/scanner/tool/search, pagination, clickable rows for detail view
- **Duplicates tab** — Grouped findings by tool + title + severity across scans
- **Diff tab** — Side-by-side comparison between any two scans
- **Scans tab** — Historical scan table with severity counts
- **Auto-refresh** — Configurable auto-refresh interval
- **Finding detail page** — Full details including raw JSON data

## Supported Scanners

| Scanner | CLI Name | Format |
|---------|----------|--------|
| Cisco MCP Scanner | `cisco-mcp` | `scan_results` with analyzer-grouped findings |
| Cisco A2A Scanner | `cisco-a2a` | `findings` with AI Security Taxonomy metadata |
| mcp-scan (Invariant Labs) | `mcp-scan` / `mcpscan` | `issues` array with severity codes |
| MCPwn (ressl) | `mcpwn` | Standard findings with MCP-XXX IDs |
| MCPwn (Teycir legacy) | `mcpwn` | Legacy test-based format |
| SARIF | `sarif` | Standard SARIF 2.1 format |

## Screenshots

| Dashboard Overview | Findings Table |
|---|---|
| ![Overview](https://via.placeholder.com/600x300/1e293b/3b82f6?text=Severity+Pie+%2B+Trend+%2B+Top+Tools) | ![Findings](https://via.placeholder.com/600x300/1e293b/3b82f6?text=Filterable+Findings+Table) |
| **Scan Diff** | **Finding Detail** |
| ![Diff](https://via.placeholder.com/600x300/1e293b/3b82f6?text=Scan+Comparison) | ![Detail](https://via.placeholder.com/600x300/1e293b/3b82f6?text=Finding+Detail+View) |

_Run `mcpscope seed && mcpscope serve` and open http://localhost:8080 to see the live dashboard._

## CI/CD Integration

Secure the API with an API key:
```bash
mcpscope config set api_key "your-secret-key"
mcpscope serve
# All /api/* endpoints now require: X-API-Key: your-secret-key
```

A [GitHub Actions workflow](.github/workflows/scan.yml) is included for automated scanning.

Slack alerts for critical/high findings:
```bash
mcpscope config set slack_webhook_url "https://hooks.slack.com/services/..."
```

Webhook URLs for custom integrations:
```bash
mcpscope config set webhook_urls '["https://your-server.com/webhook"]'
```

## Configuration

Config file at `~/.mcpscope/config.json`:

```bash
mcpscope config show
mcpscope config set port 9090
mcpscope config set auto_refresh_seconds 60
mcpscope config set max_upload_mb 100
```

## Docker

```bash
docker build -t mcpscope .
docker run -p 8080:8080 -v mcpscope-data:/root/.mcpscope mcpscope
```

## Development

```bash
pip install -e ".[dev]"
pytest
```

## Security Events (MCPGuard Integration)

MCP-Scope can receive real-time security events from MCPGuard:

```bash
# Configure MCPGuard's config.yaml:
mcpscop_url: http://localhost:8000

# Events appear in the "Live Events" dashboard tab
```

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/events` | POST | Ingest a security event |
| `/api/events` | GET | List events (filters: severity, event_type) |
| `/api/events/stats` | GET | Event statistics |
| `/api/events` | DELETE | Clear all events |

## Related Projects

MCPscop is part of the **Carlos-Projects** security ecosystem for AI agents:

- [**MCPGuard**](https://github.com/Carlos-Projects/mcpguard) — Runtime security proxy for MCP/A2A protocols with HTMX dashboard
- [**MCPwn**](https://github.com/Carlos-Projects/mcpwn) — Offensive security testing framework for MCP servers
- [**Palisade Scanner**](https://github.com/Carlos-Projects/palisade-scanner) — Scan web content for prompt injection and adversarial content
- [**AgentGate**](https://github.com/Carlos-Projects/agentgate) — Policy-based firewall and honeypot middleware for AI agents accessing websites

## License

[MIT](LICENSE)

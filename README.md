# MCP-Scope

Unified security dashboard for MCP/A2A scanner results.

Consumes output from multiple MCP/A2A security scanners (Cisco MCP Scanner, Cisco A2A Scanner, mcp-scan, MCPwn, SARIF) and presents a consolidated view of your security posture.

## Quick Start

```bash
pip install -e .

# Generate demo data and explore
mcpscope seed
mcpscope serve

# Import results from different scanners
mcpscope import cisco-mcp results.json
mcpscope import cisco-a2a results.json
mcpscope import mcpwn results.json
mcpscope import sarif report.sarif

# Export a compliance report
mcpscope report --format pdf --output security-report.pdf

# Backup/Restore
mcpscope backup backup.db
mcpscope restore backup.db
```

## Commands

| Command | Description |
|---------|-------------|
| `serve` | Start the FastAPI web dashboard |
| `import` | Import scanner JSON/SARIF results into SQLite |
| `report` | Export JSON, CSV, or PDF compliance report |
| `seed` | Generate demo scan data |
| `backup` | Backup the SQLite database |
| `restore` | Restore the SQLite database from backup |
| `config` | View or set configuration options |

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /` | Dashboard UI with filters and tabs |
| `GET /findings/{id}` | Finding detail page |
| `GET /api/health` | Health check |
| `GET /api/scans` | List scans (paginated) |
| `GET /api/scans/{id}` | Scan details with findings (paginated) |
| `GET /api/findings` | Query findings (paginated, filter by severity/scanner/tool/search) |
| `GET /api/findings/{id}` | Single finding with full detail |
| `GET /api/stats/summary` | Aggregated statistics |
| `GET /api/stats/top-tools` | Most vulnerable tools |
| `GET /api/stats/severity-trend` | Findings over time |
| `GET /api/stats/scanners` | List distinct scanners |
| `GET /api/stats/tool-names` | List distinct tool names |
| `GET /api/report/json` | Full JSON report |

## Dashboard Features

- **Overview tab** — Severity pie chart, top tools bar chart, severity trend over time
- **Findings tab** — Filterable table with severity/scanner/tool/search, pagination, clickable rows for detail view
- **Scans tab** — Historical scan table with severity counts
- **Auto-refresh** — Configurable auto-refresh interval
- **Finding detail page** — Full details including raw data

## Supported Scanners

| Scanner | CLI Name | Format |
|---------|----------|--------|
| Cisco MCP Scanner | `cisco-mcp` | `scan_results` with analyzer-grouped findings |
| Cisco A2A Scanner | `cisco-a2a` | `findings` with AI Security Taxonomy metadata |
| mcp-scan (Invariant Labs) | `mcp-scan` / `mcpscan` | `issues` array with severity codes |
| MCPwn (ressl) | `mcpwn` | Standard findings with MCP-XXX IDs |
| MCPwn (Teycir legacy) | `mcpwn` | Legacy test-based format |
| SARIF | `sarif` | Standard SARIF 2.1 format |

## Configuration

Config file at `~/.mcpscope/config.json`:

```bash
mcpscope config show
mcpscope config set port 9090
mcpscope config set auto_refresh_seconds 60
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

# Changelog

## [0.1.0] - 2026-05-23

### Added
- Initial release of MCP-Scope
- Parse and import results from Cisco MCP Scanner, Cisco A2A Scanner, mcp-scan, MCPwn, and SARIF
- Web dashboard with Plotly charts (severity pie, top tools bar, severity trend)
- REST API with pagination, filtering, search, and scan diff
- CLI: `serve`, `scan`, `import`, `report` (json/csv/pdf), `seed`, `prune`, `backup`, `restore`, `config`
- SQLite storage with scan history and deduplication
- Webhook and Slack alerts for critical/high findings
- API key authentication for CI/CD integration
- Dockerfile and GitHub Actions workflow
- Auto-refresh, finding detail view, scan comparison (diff)
- File size validation on import
- 46 unit and HTTP integration tests

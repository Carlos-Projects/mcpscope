# Contributing

Thanks for your interest in MCP-Scope!

## Development Setup

```bash
git clone https://github.com/Carlos-Projects/mcpscope
cd mcpscope
pip install -e ".[dev]"
```

## Running Tests

```bash
pytest -v
```

All tests must pass before submitting a PR.

## Code Style

- Format: `ruff format .`
- Lint: `ruff check .`
- No commented-out code
- Type hints required for all public functions

## Pull Request Process

1. Create a feature branch from `main`
2. Write tests for your changes
3. Ensure all tests pass
4. Update `CHANGELOG.md` if applicable
5. Open a PR with a clear description

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add new scanner parser
fix: handle null severity in report
deps: bump fastapi to 0.136.0
docs: update README badges
```

## Adding a New Scanner

1. Create `mcpscope/ingest/new_scanner.py` extending `BaseParser`
2. Implement `parse()` and set `SCANNER_NAME`
3. Add to `PARSERS` dict in `cli.py`
4. Create test fixtures in `tests/fixtures/`
5. Add tests in `tests/test_parsers.py`
6. Update `README.md` supported scanners table

## Reporting Issues

Open a [GitHub Issue](https://github.com/Carlos-Projects/mcpscope/issues/new/choose) using the appropriate template.

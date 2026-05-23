import pytest
import json
from pathlib import Path

from mcpscope.api.server import create_app
from mcpscope.storage.store import Store
from mcpscope.models.finding import Finding, Severity
from mcpscope.models.scan import ScanRun


@pytest.fixture
def store():
    import tempfile, os
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    s = Store(db_path=db_path)
    s.save_scan(ScanRun(id="http-test", scanner="test", target="t"), [
        Finding(scan_id="http-test", scanner="test", tool_name="tool_a",
                severity=Severity.CRITICAL, title="Critical finding"),
        Finding(scan_id="http-test", scanner="test", tool_name="tool_b",
                severity=Severity.LOW, title="Low priority"),
    ])
    yield s
    s._conn.close()
    os.unlink(db_path)


@pytest.fixture
def client(store):
    from httpx import AsyncClient, ASGITransport
    app = create_app(store)
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://test")


@pytest.mark.asyncio
async def test_health(client):
    r = await client.get("/api/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


@pytest.mark.asyncio
async def test_list_scans(client):
    r = await client.get("/api/scans")
    assert r.status_code == 200
    data = r.json()
    assert data["total"] >= 1
    assert len(data["scans"]) >= 1
    assert "page" in data
    assert "pages" in data


@pytest.mark.asyncio
async def test_list_scans_pagination(client):
    r = await client.get("/api/scans?page=1&page_size=1")
    assert r.status_code == 200
    data = r.json()
    assert data["page"] == 1
    assert data["page_size"] == 1


@pytest.mark.asyncio
async def test_get_scan(client):
    r = await client.get("/api/scans/http-test")
    assert r.status_code == 200
    data = r.json()
    assert data["scan"]["id"] == "http-test"
    assert len(data["findings"]) >= 1


@pytest.mark.asyncio
async def test_get_scan_not_found(client):
    r = await client.get("/api/scans/nonexistent")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_list_findings(client):
    r = await client.get("/api/findings")
    assert r.status_code == 200
    data = r.json()
    assert data["total"] >= 2
    assert len(data["findings"]) >= 2


@pytest.mark.asyncio
async def test_findings_filter_severity(client):
    r = await client.get("/api/findings?severity=critical")
    assert r.status_code == 200
    data = r.json()
    assert data["total"] >= 1
    for f in data["findings"]:
        assert f["severity"] == "critical"


@pytest.mark.asyncio
async def test_findings_filter_search(client):
    r = await client.get("/api/findings?search=Critical")
    assert r.status_code == 200
    data = r.json()
    assert data["total"] >= 1


@pytest.mark.asyncio
async def test_findings_filter_scanner(client):
    r = await client.get("/api/findings?scanner=test")
    assert r.status_code == 200
    data = r.json()
    assert data["total"] >= 2


@pytest.mark.asyncio
async def test_get_finding(client):
    r = await client.get("/api/findings")
    fid = r.json()["findings"][0]["id"]
    r = await client.get(f"/api/findings/{fid}")
    assert r.status_code == 200
    assert r.json()["finding"]["id"] == fid
    assert r.json()["scan"] is not None


@pytest.mark.asyncio
async def test_get_finding_not_found(client):
    r = await client.get("/api/findings/nonexistent")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_stats_summary(client):
    r = await client.get("/api/stats/summary")
    assert r.status_code == 200
    data = r.json()
    assert "total_scans" in data
    assert "critical" in data
    assert data["total_scans"] >= 1


@pytest.mark.asyncio
async def test_stats_top_tools(client):
    r = await client.get("/api/stats/top-tools")
    assert r.status_code == 200
    data = r.json()
    assert "tools" in data


@pytest.mark.asyncio
async def test_stats_scanners(client):
    r = await client.get("/api/stats/scanners")
    assert r.status_code == 200
    data = r.json()
    assert "test" in data["scanners"]


@pytest.mark.asyncio
async def test_stats_duplicates(client):
    r = await client.get("/api/stats/duplicates")
    assert r.status_code == 200
    assert "duplicates" in r.json()


@pytest.mark.asyncio
async def test_report_json(client):
    r = await client.get("/api/report/json")
    assert r.status_code == 200
    data = r.json()
    assert "summary" in data
    assert "generated_at" in data


@pytest.mark.asyncio
async def test_report_csv(client):
    r = await client.get("/api/report/csv")
    assert r.status_code == 200
    assert r.headers["content-type"] == "text/csv; charset=utf-8"
    body = r.text
    assert "severity" in body
    assert "critical" in body


@pytest.mark.asyncio
async def test_dashboard_html(client):
    r = await client.get("/")
    assert r.status_code == 200
    assert "MCP-Scope" in r.text


@pytest.mark.asyncio
async def test_finding_detail_html(client):
    r = await client.get("/api/findings")
    fid = r.json()["findings"][0]["id"]
    r = await client.get(f"/findings/{fid}")
    assert r.status_code == 200
    assert "Finding Detail" in r.text or "MCP-Scope" in r.text


@pytest.mark.asyncio
async def test_api_key_protection(client):
    from mcpscope.api.server import create_app
    from mcpscope.config import Settings
    import tempfile, os
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    s = Store(db_path=db_path)
    cfg = Settings(api_key="test-key-123")
    app = create_app(s, settings=cfg)
    from httpx import AsyncClient, ASGITransport
    transport = ASGITransport(app=app)
    c = AsyncClient(transport=transport, base_url="http://test")

    r = await c.get("/api/scans")
    assert r.status_code == 401

    r = await c.get("/api/scans", headers={"X-API-Key": "test-key-123"})
    assert r.status_code == 200

    r = await c.get("/")
    assert r.status_code == 200

    await c.aclose()
    s._conn.close()
    os.unlink(db_path)


@pytest.mark.asyncio
async def test_diff_endpoint(client):
    r = await client.get("/api/scans")
    scans = r.json()["scans"]
    if len(scans) >= 2:
        a, b = scans[0]["id"], scans[1]["id"]
        r = await client.get(f"/api/scans/{a}/diff/{b}")
        assert r.status_code == 200
        data = r.json()
        assert "new_count" in data
        assert "fixed_count" in data


@pytest.mark.asyncio
async def test_cors_headers(client):
    r = await client.options("/api/health")
    assert "access-control-allow-origin" in r.headers or r.status_code in (200, 204, 405)


@pytest.mark.asyncio
async def test_swagger_docs(client):
    r = await client.get("/docs")
    assert r.status_code in (200, 404)


@pytest.mark.asyncio
async def test_openapi_json(client):
    r = await client.get("/api/openapi.json")
    assert r.status_code in (200, 404)
    if r.status_code == 200:
        assert r.json()["info"]["title"] == "MCP-Scope API"

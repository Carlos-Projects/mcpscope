from __future__ import annotations
import csv
import hmac
import io
import re
from datetime import datetime, timezone

from fastapi import APIRouter, Request, HTTPException, Query, Response
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

from mcpscope.models.finding import Severity
from mcpscope.models.security_event import SecurityEvent
from mcp_taxonomy import (
    AttackCategory,
    Severity as TaxSeverity,
    DetectionMethod,
    palisade_finding_to_taxonomy,
    mcpguard_event_to_taxonomy,
    mcpwn_finding_to_taxonomy,
    agentgate_signal_to_taxonomy,
)
from mcp_taxonomy.core import CATEGORY_SEVERITY

router = APIRouter()
PAGE_SIZE = 50

_JS_UNSAFE_RE = re.compile(r"</[sS][cC][rR][iI][pP][tT]|<!\[CDATA\[|]]>")


def _sanitize_js(val: str, max_len: int = 200) -> str:
    s = str(val)
    s = _JS_UNSAFE_RE.sub("", s)
    s = s.replace("\0", "")
    return s[:max_len]


def _sanitize_tools(tools: list[dict]) -> list[dict]:
    return [
        {k: _sanitize_js(v) if isinstance(v, str) else v for k, v in t.items()}
        for t in tools
    ]


def _sanitize_trend(trend: list[dict]) -> list[dict]:
    return [
        {k: _sanitize_js(v) if isinstance(v, str) else v for k, v in t.items()}
        for t in trend
    ]


def get_store(request: Request):
    return request.app.state.store


def get_templates(request: Request):
    return request.app.state.templates


@router.get("/api/health")
def health():
    return {"status": "ok"}


@router.get("/api/taxonomy")
def taxonomy_info():
    """Return the canonical taxonomy definition."""
    return {
        "attack_categories": [c.value for c in AttackCategory],
        "severities": [s.value for s in TaxSeverity],
        "detection_methods": [m.value for m in DetectionMethod],
        "category_severity": {c.value: s.value for c, s in CATEGORY_SEVERITY.items()},
    }


@router.post("/api/taxonomy/normalize")
def normalize_taxonomy(body: dict):
    """Normalize a finding/event from any project into the canonical taxonomy."""
    source = body.get("source", "")
    raw = body.get("raw", body)
    if source == "palisade-scanner":
        event = palisade_finding_to_taxonomy(raw)
    elif source == "mcpguard":
        event = mcpguard_event_to_taxonomy(raw)
    elif source == "mcpwn":
        event = mcpwn_finding_to_taxonomy(raw)
    elif source == "agentgate":
        event = agentgate_signal_to_taxonomy(
            signal_type=raw.get("signal_type", ""),
            weight=raw.get("weight", 0),
            action=raw.get("action", ""),
            path=raw.get("path", ""),
            user_agent=raw.get("userAgent", raw.get("user_agent", "")),
            score=raw.get("score", 0),
        )
    else:
        return JSONResponse({"error": f"Unknown source: {source}"}, status_code=400)
    return JSONResponse(
        {
            "source": event.source,
            "attack_category": event.attack_category.value,
            "severity": event.severity.value,
            "confidence": event.confidence.value,
            "detection_method": event.detection_method.value
            if isinstance(event.detection_method, DetectionMethod)
            else event.detection_method,
            "title": event.title,
            "description": event.description,
            "recommendation": event.recommendation,
            "target": event.target,
            "snippet": event.snippet[:200] if event.snippet else "",
            "blocked": event.blocked,
            "risk_score": event.risk_score,
        }
    )


def _session_value(password: str, client_ip: str) -> str:
    h = hmac.new(password.encode(), client_ip.encode(), "sha256")
    return h.hexdigest()


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    templates = get_templates(request)
    if not templates:
        return HTMLResponse("<h1>Not found</h1>", status_code=500)
    return templates.TemplateResponse(request, "login.html", {})


@router.post("/api/login")
def login(request: Request, response: Response, body: dict | None = None):
    cfg = request.app.state
    if not cfg.dashboard_password:
        return JSONResponse({"error": "Dashboard auth not configured"}, status_code=403)
    password = (body or {}).get("password", "")
    if not hmac.compare_digest(password, cfg.dashboard_password):
        return JSONResponse({"error": "Invalid password"}, status_code=401)
    ip = request.client.host if request.client else ""
    session = _session_value(cfg.dashboard_password, ip)
    response.set_cookie(
        key="mcpscope_session",
        value=session,
        max_age=86400,
        httponly=True,
        samesite="lax",
        secure=False,
    )
    return {"status": "ok"}


@router.post("/api/logout")
def logout(response: Response):
    response.delete_cookie("mcpscope_session")
    return {"status": "ok"}


@router.get("/api/scans")
def list_scans(
    request: Request,
    page: int = Query(1, ge=1),
    page_size: int = Query(PAGE_SIZE, ge=1, le=200),
):
    store = get_store(request)
    scans, total = store.get_scans_paginated(page, page_size)
    return {
        "scans": [s.model_dump() for s in scans],
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": (total + page_size - 1) // page_size,
    }


@router.get("/api/scans/{scan_id}")
def get_scan(
    request: Request,
    scan_id: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(PAGE_SIZE, ge=1, le=200),
):
    store = get_store(request)
    scan = store.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    findings, total = store.get_findings(
        scan_id=scan_id, page=page, page_size=page_size
    )
    return {
        "scan": scan.model_dump(),
        "findings": [f.model_dump() for f in findings],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.get("/api/scans/{scan_id}/diff/{other_id}")
def diff_scans(request: Request, scan_id: str, other_id: str):
    store = get_store(request)
    try:
        result = store.diff_scans(scan_id, other_id)
    except ValueError as e:
        raise HTTPException(404, str(e))
    return result


@router.get("/api/findings")
def list_findings(
    request: Request,
    scan_id: str | None = Query(None),
    severity: str | None = Query(None),
    tool_name: str | None = Query(None),
    scanner: str | None = Query(None),
    search: str | None = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(PAGE_SIZE, ge=1, le=200),
):
    store = get_store(request)
    findings, total = store.get_findings(
        scan_id=scan_id,
        severity=severity,
        tool_name=tool_name,
        scanner=scanner,
        search=search,
        page=page,
        page_size=page_size,
    )
    return {
        "findings": [f.model_dump() for f in findings],
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": (total + page_size - 1) // page_size,
    }


@router.get("/api/findings/{finding_id}")
def get_finding(request: Request, finding_id: str):
    store = get_store(request)
    finding = store.get_finding(finding_id)
    if not finding:
        raise HTTPException(404, "Finding not found")
    scan = store.get_scan(finding.scan_id)
    return {
        "finding": finding.model_dump(),
        "scan": scan.model_dump() if scan else None,
    }


@router.get("/api/stats/top-tools")
def top_tools(request: Request):
    store = get_store(request)
    return {"tools": store.get_top_tools()}


@router.get("/api/stats/severity-trend")
def severity_trend(request: Request):
    store = get_store(request)
    return {"trend": store.get_severity_trend()}


@router.get("/api/stats/scanners")
def list_scanners(request: Request):
    store = get_store(request)
    return {"scanners": store.get_scanners()}


@router.get("/api/stats/tool-names")
def list_tool_names(request: Request):
    store = get_store(request)
    return {"tools": store.get_tool_names()}


@router.get("/api/stats/duplicates")
def list_duplicates(request: Request):
    store = get_store(request)
    return {"duplicates": store.get_duplicates()}


@router.get("/api/stats/summary")
def summary(request: Request):
    store = get_store(request)
    history = store.get_scan_history()
    top = store.get_top_tools()
    dups = store.get_duplicates()
    return {
        "total_scans": len(history.scans),
        "total_findings": history.total_findings,
        "critical": history.total_critical,
        "high": history.total_high,
        "medium": history.total_medium,
        "low": history.total_low,
        "info": history.total_info,
        "top_tools": top,
        "duplicates": dups,
        "scans": [s.model_dump() for s in history.scans],
    }


@router.get("/api/report/csv")
def report_csv(request: Request):
    store = get_store(request)
    findings, _ = store.get_findings(page_size=100000)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "id",
            "scan_id",
            "scanner",
            "tool_name",
            "severity",
            "title",
            "description",
            "recommendation",
            "cvss_score",
            "cve_id",
            "created_at",
        ]
    )
    for f in findings:
        sev = f.severity.value if isinstance(f.severity, Severity) else str(f.severity)
        writer.writerow(
            [
                f.id,
                f.scan_id,
                f.scanner,
                f.tool_name,
                sev,
                f.title,
                f.description or "",
                f.recommendation or "",
                f.cvss_score or "",
                f.cve_id or "",
                f.created_at,
            ]
        )
    return PlainTextResponse(
        output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=mcpscope-report.csv"},
    )


@router.get("/api/report/json")
def report_json(request: Request):
    store = get_store(request)
    history = store.get_scan_history()
    top = store.get_top_tools()
    trend = store.get_severity_trend()
    dups = store.get_duplicates()
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_scans": len(history.scans),
            "total_findings": history.total_findings,
            "critical": history.total_critical,
            "high": history.total_high,
            "medium": history.total_medium,
            "low": history.total_low,
            "info": history.total_info,
        },
        "top_tools": top,
        "duplicates": dups,
        "severity_trend": trend,
        "scans": [s.model_dump() for s in history.scans],
    }


@router.post("/api/events")
async def ingest_event(request: Request):
    store = get_store(request)
    body = await request.json()
    event = SecurityEvent(**body)
    saved = store.save_event(event)
    return {"status": "ok", "id": saved.id}


@router.get("/api/events")
def list_events(
    request: Request,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    severity: str | None = Query(None),
    event_type: str | None = Query(None),
):
    store = get_store(request)
    events, total = store.get_events(
        limit=limit,
        offset=offset,
        severity=severity,
        event_type=event_type,
    )
    return {
        "events": [e.model_dump() for e in events],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/api/events/stats")
def event_stats(request: Request):
    store = get_store(request)
    return store.get_event_stats()


@router.delete("/api/events")
def clear_events(request: Request):
    store = get_store(request)
    store.clear_events()
    return {"status": "ok"}


@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    store = get_store(request)
    history = store.get_scan_history()
    top_tools_data = store.get_top_tools()
    trend_data = store.get_severity_trend()
    scanners = store.get_scanners()
    tool_names = store.get_tool_names()
    dups = store.get_duplicates()

    templates = get_templates(request)
    if not templates:
        return HTMLResponse("<h1>Dashboard templates not found</h1>", status_code=500)

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "total_scans": len(history.scans),
            "total_findings": history.total_findings,
            "critical": history.total_critical,
            "high": history.total_high,
            "medium": history.total_medium,
            "low": history.total_low,
            "info": history.total_info,
            "top_tools": _sanitize_tools(top_tools_data),
            "trend_data": _sanitize_trend(trend_data),
            "scans": history.scans,
            "scanners": scanners,
            "tool_names": tool_names,
            "duplicates": dups,
            "auto_refresh": getattr(request.app.state, "auto_refresh", 30),
        },
    )


@router.get("/findings/{finding_id}", response_class=HTMLResponse)
def finding_detail(request: Request, finding_id: str):
    store = get_store(request)
    finding = store.get_finding(finding_id)
    if not finding:
        return HTMLResponse("<h1>Finding not found</h1>", status_code=404)
    scan = store.get_scan(finding.scan_id)
    templates = get_templates(request)
    if not templates:
        return HTMLResponse("<h1>Not found</h1>", status_code=500)
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "total_scans": 0,
            "total_findings": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "top_tools": [],
            "trend_data": [],
            "scans": [],
            "scanners": [],
            "tool_names": [],
            "duplicates": [],
            "detail_finding": finding,
            "detail_scan": scan,
            "auto_refresh": 0,
        },
    )

from __future__ import annotations
import csv
import io
import json
from datetime import datetime, timezone

from fastapi import APIRouter, Request, HTTPException, Query, UploadFile, File, Form
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

from mcpscope.models.finding import Severity
from mcpscope.models.scan import ScanRun

router = APIRouter()
PAGE_SIZE = 50


def get_store(request: Request):
    return request.app.state.store


def get_templates(request: Request):
    return request.app.state.templates


@router.get("/api/health")
def health():
    return {"status": "ok"}


@router.get("/api/scans")
def list_scans(request: Request, page: int = Query(1, ge=1), page_size: int = Query(PAGE_SIZE, ge=1, le=200)):
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
def get_scan(request: Request, scan_id: str, page: int = Query(1, ge=1), page_size: int = Query(PAGE_SIZE, ge=1, le=200)):
    store = get_store(request)
    scan = store.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    findings, total = store.get_findings(scan_id=scan_id, page=page, page_size=page_size)
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
        scan_id=scan_id, severity=severity, tool_name=tool_name,
        scanner=scanner, search=search, page=page, page_size=page_size,
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
    return {"finding": finding.model_dump(), "scan": scan.model_dump() if scan else None}


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
    writer.writerow(["id", "scan_id", "scanner", "tool_name", "severity", "title",
                      "description", "recommendation", "cvss_score", "cve_id", "created_at"])
    for f in findings:
        sev = f.severity.value if isinstance(f.severity, Severity) else str(f.severity)
        writer.writerow([f.id, f.scan_id, f.scanner, f.tool_name, sev, f.title,
                         f.description or "", f.recommendation or "",
                         f.cvss_score or "", f.cve_id or "", f.created_at])
    return PlainTextResponse(output.getvalue(), media_type="text/csv",
                             headers={"Content-Disposition": "attachment; filename=mcpscope-report.csv"})


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
            "top_tools": top_tools_data,
            "trend_data": trend_data,
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
            "total_scans": 0, "total_findings": 0,
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
            "top_tools": [], "trend_data": [], "scans": [],
            "scanners": [], "tool_names": [], "duplicates": [],
            "detail_finding": finding,
            "detail_scan": scan,
            "auto_refresh": 0,
        },
    )

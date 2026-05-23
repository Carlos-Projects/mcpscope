from __future__ import annotations
import json
from typing import Any

import httpx
from mcpscope.models.finding import Finding, Severity


async def fire_webhooks(webhooks: list[str], event: str, payload: dict):
    if not webhooks:
        return
    async with httpx.AsyncClient(timeout=10) as client:
        for url in webhooks:
            try:
                await client.post(url, json={"event": event, **payload})
            except Exception:
                pass


def _build_slack_message(scan_id: str, scanner: str, summary: dict, alerts: list[dict]) -> dict:
    color = "#dc2626" if summary.get("critical_count", 0) > 0 else "#ea580c"
    fields = [
        {"title": "Scanner", "value": scanner, "short": True},
        {"title": "Findings", "value": str(summary.get("findings_count", 0)), "short": True},
        {"title": "Critical", "value": str(summary.get("critical_count", 0)), "short": True},
        {"title": "High", "value": str(summary.get("high_count", 0)), "short": True},
    ]
    attachments = []
    for a in alerts[:5]:
        attachments.append({
            "color": "#dc2626" if a["severity"] == "critical" else "#ea580c",
            "title": f"[{a['severity'].upper()}] {a['title']}",
            "text": a.get("description", "") or "",
            "fields": [{"title": "Tool", "value": a["tool"], "short": True}],
        })
    return {
        "username": "MCP-Scope",
        "icon_emoji": ":shield:",
        "text": f"*MCP-Scope Alert* — Scan `{scan_id[:12]}...` ({scanner})",
        "attachments": [{"color": color, "fields": fields}] + attachments,
    }


async def fire_slack(slack_url: str, scan_id: str, scanner: str,
                     summary: dict, alerts: list[dict]):
    if not slack_url:
        return
    msg = _build_slack_message(scan_id, scanner, summary, alerts)
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(slack_url, json=msg)
    except Exception:
        pass


def notify_scan_imported(webhooks: list[str], findings: list[Finding],
                         findings_count: int, critical_count: int, high_count: int,
                         scan_id: str = "", scanner: str = "",
                         slack_url: str = ""):
    if (critical_count == 0 and high_count == 0) or (not webhooks and not slack_url):
        return

    critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
    high_findings = [f for f in findings if f.severity == Severity.HIGH]

    summary = {
        "scan_id": scan_id,
        "scanner": scanner,
        "findings_count": findings_count,
        "critical_count": critical_count,
        "high_count": high_count,
    }

    alerts = []
    for f in critical_findings[:10]:
        alerts.append({
            "severity": "critical",
            "tool": f.tool_name,
            "title": f.title,
            "description": f.description,
            "finding_id": f.id,
        })
    for f in high_findings[:10]:
        alerts.append({
            "severity": "high",
            "tool": f.tool_name,
            "title": f.title,
            "description": f.description,
            "finding_id": f.id,
        })

    import asyncio
    if webhooks:
        payload = {"event": "scan_imported", "summary": summary, "alerts": alerts}
        try:
            asyncio.create_task(fire_webhooks(webhooks, "scan_imported", payload))
        except RuntimeError:
            pass
    if slack_url:
        try:
            asyncio.create_task(fire_slack(slack_url, scan_id, scanner, summary, alerts))
        except RuntimeError:
            pass

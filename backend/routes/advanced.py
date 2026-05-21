"""
routes/advanced.py
Phase 5 endpoints:
  POST /api/attack-simulate  — AI attack walkthrough
  POST /api/repo-scan        — GitHub repo scanner (SSE progress)
  POST /api/dep-scan         — Dependency CVE checker
  POST /api/rewrite          — Secure code rewriter
"""
from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse, StreamingResponse
from pydantic import BaseModel
from typing import Optional
import json

from ai.attack_simulator import simulate_attack
from ai.rewriter import rewrite_secure
from services.repo_scanner import scan_repo
from services.dep_scanner import (
    parse_requirements_txt, parse_pyproject_toml, check_dependencies
)

router = APIRouter()


# ── Attack simulation ──────────────────────────────────────────────────────

class AttackRequest(BaseModel):
    vulnerability: dict   # Vulnerability dict from a prior scan result


@router.post("/attack-simulate")
async def attack_simulate(req: AttackRequest):
    try:
        result = await simulate_attack(req.vulnerability)
        return result
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))


# ── Repo scan (Server-Sent Events for live progress) ───────────────────────

class RepoScanRequest(BaseModel):
    github_url: str


@router.post("/repo-scan")
async def repo_scan(req: RepoScanRequest):
    """
    Streams Server-Sent Events: {pct, message} then {result: ...} when done.
    Frontend reads via EventSource or fetch + ReadableStream.
    """
    events: list[str] = []

    def progress(pct: int, msg: str):
        events.append(json.dumps({"pct": pct, "message": msg}))

    async def generate():
        import asyncio
        # Run blocking repo scan in thread pool
        loop = asyncio.get_event_loop()

        # Kick off scan
        task = loop.run_in_executor(None, lambda: None)  # placeholder
        result_holder: dict = {}

        async def run():
            result_holder["data"] = await scan_repo(req.github_url, progress)

        scan_task = asyncio.create_task(run())

        sent = 0
        while not scan_task.done():
            while sent < len(events):
                yield f"data: {events[sent]}\n\n"
                sent += 1
            await asyncio.sleep(0.1)

        await scan_task
        while sent < len(events):
            yield f"data: {events[sent]}\n\n"
            sent += 1

        yield f"data: {json.dumps({'result': result_holder.get('data', {})})}\n\n"

    return StreamingResponse(generate(), media_type="text/event-stream")


# ── Dependency scan ────────────────────────────────────────────────────────

class DepScanRequest(BaseModel):
    content: str                      # raw file contents
    filename: str = "requirements.txt"


@router.post("/dep-scan")
async def dep_scan(req: DepScanRequest):
    if req.filename.endswith("pyproject.toml"):
        deps = parse_pyproject_toml(req.content)
    else:
        deps = parse_requirements_txt(req.content)

    if not deps:
        raise HTTPException(status_code=422, detail="No dependencies found in file")

    results = await check_dependencies(deps)
    vulnerable = [r for r in results if r.get("status") == "vulnerable"]
    return {
        "total": len(results),
        "vulnerable_count": len(vulnerable),
        "dependencies": results,
    }


# ── Secure rewrite ─────────────────────────────────────────────────────────

class RewriteRequest(BaseModel):
    code: str
    vulnerabilities: list[dict]


@router.post("/rewrite")
async def rewrite(req: RewriteRequest):
    if not req.code.strip():
        raise HTTPException(status_code=422, detail="code must not be empty")
    if not req.vulnerabilities:
        raise HTTPException(status_code=422, detail="vulnerabilities list is empty")
    try:
        result = await rewrite_secure(req.code, req.vulnerabilities)
        return result
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))


class ReportRequest(BaseModel):
    result: dict


@router.post("/report", response_class=PlainTextResponse)
async def report(req: ReportRequest):
    result = req.result
    vulns = result.get("vulnerabilities", [])
    lines = [
        "# Novapilot Security Report",
        "",
        f"Scan ID: {result.get('scan_id') or result.get('id', 'unknown')}",
        f"Language: {result.get('language', 'unknown')}",
        f"Risk score: {result.get('risk_score', 0)}",
        f"Summary: {result.get('summary', '')}",
        "",
        "## Findings",
        "",
    ]
    if not vulns:
        lines.append("No vulnerabilities were detected.")
    for i, vuln in enumerate(vulns, start=1):
        lines.extend([
            f"### {i}. {vuln.get('title', 'Security finding')}",
            "",
            f"- Severity: {vuln.get('severity', 'INFO')}",
            f"- Line: {vuln.get('line', '?')}",
            f"- OWASP: {vuln.get('owasp') or 'Unmapped'}",
            f"- CWE: {vuln.get('cwe') or 'Unmapped'}",
            "",
            vuln.get("explanation", ""),
            "",
            "Recommended fix:",
            "",
            "```",
            vuln.get("fix", ""),
            "```",
            "",
        ])
    return "\n".join(lines)

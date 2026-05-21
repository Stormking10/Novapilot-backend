"""
routes/scan.py
POST /api/scan  — the main vulnerability scanning endpoint
"""
import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException
from models.scan import ScanRequest, ScanResult, Vulnerability, Language, Severity
from scanners.semgrep import run_semgrep
from ai.explainer import explain_vulnerabilities
from services.history_store import save_scan

router = APIRouter()

_VALID_SEVERITIES = {s.value for s in Severity}


def _normalize_severity(value: str | None) -> Severity:
    if not value:
        return Severity.INFO
    upper = str(value).strip().upper()
    if upper in _VALID_SEVERITIES:
        return Severity(upper)
    return Severity.INFO


@router.post("/scan", response_model=ScanResult)
async def scan_code(req: ScanRequest) -> ScanResult:
    """
    1. Run Semgrep on the submitted code
    2. Pass code + Semgrep findings to AI explainer
    3. Return merged, enriched results
    """
    if not req.code.strip():
        raise HTTPException(status_code=422, detail="code must not be empty")

    # --- Step 1: Static analysis ---
    semgrep_out = run_semgrep(req.code, req.language.value)
    findings    = semgrep_out.get("findings", [])

    # --- Step 2: AI enrichment ---
    try:
        ai_result = await explain_vulnerabilities(
            code=req.code,
            semgrep_findings=findings,
            language=req.language.value,
        )
    except Exception as e:
        raise HTTPException(
            status_code=502,
            detail=f"AI explainer error: {str(e)}"
        )

    # --- Step 3: Merge Semgrep rule_id + cwe back into AI vulns ---
    semgrep_by_line: dict[str, dict] = {f["line"]: f for f in findings}
    vulns: list[Vulnerability] = []

    for i, v in enumerate(ai_result.get("vulnerabilities", [])):
        sg = semgrep_by_line.get(v.get("line", ""), {})
        vulns.append(Vulnerability(
            id          = v.get("id", f"vuln-{i+1}"),
            title       = v.get("title", "Unknown"),
            severity    = _normalize_severity(v.get("severity")),
            line        = v.get("line", "?"),
            owasp       = v.get("owasp") or sg.get("owasp"),
            rule_id     = sg.get("rule_id"),
            explanation = v.get("explanation", ""),
            fix         = v.get("fix", ""),
            cwe         = v.get("cwe") or sg.get("cwe"),
        ))

    scan_id = str(uuid.uuid4())
    result = ScanResult(
        scan_id         = scan_id,
        id              = scan_id,
        language        = req.language,
        risk_score      = int(ai_result.get("risk_score", 0)),
        summary         = ai_result.get("summary", ""),
        vulnerabilities = vulns,
        created_at      = datetime.now(timezone.utc),
        filename        = req.filename,
        scanner_output  = semgrep_out.get("raw"),
    )
    save_scan(result.model_dump(mode="json"))
    return result

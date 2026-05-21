"""
services/repo_scanner.py
Clones a GitHub repo, finds Python files, runs Semgrep + AI on each.
Requires: git on PATH, ANTHROPIC_API_KEY in env.
"""
import os
import asyncio
import shutil
import tempfile
import subprocess
from pathlib import Path
from typing import AsyncIterator

from scanners.semgrep import run_semgrep
from ai.explainer import explain_vulnerabilities


MAX_FILE_SIZE_KB = 100
MAX_FILES = 50
PYTHON_GLOB = "**/*.py"


async def scan_repo(
    github_url: str,
    progress_callback=None,
) -> dict:
    """
    Clone repo, scan all Python files, return aggregated results.
    progress_callback(pct: int, message: str) called at each stage.
    """
    tmpdir = tempfile.mkdtemp(prefix="owaspilot_")
    try:
        # 1 — clone
        _progress(progress_callback, 5, "Cloning repository…")
        _clone(github_url, tmpdir)

        # 2 — enumerate files
        _progress(progress_callback, 20, "Enumerating Python files…")
        py_files = _collect_files(tmpdir)

        # 3 — scan each file
        all_findings = []
        for i, fpath in enumerate(py_files):
            pct = 20 + int((i / max(len(py_files), 1)) * 55)
            rel = str(fpath.relative_to(tmpdir))
            _progress(progress_callback, pct, f"Scanning {rel}…")
            findings = await _scan_file(fpath, rel)
            if findings:
                all_findings.append(findings)

        # 4 — aggregate
        _progress(progress_callback, 90, "Aggregating results…")
        result = _aggregate(all_findings, py_files)
        _progress(progress_callback, 100, "Done")
        return result

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def _clone(url: str, dest: str):
    subprocess.run(
        ["git", "clone", "--depth", "1", "--quiet", url, dest],
        check=True, timeout=60,
        capture_output=True,
    )


def _collect_files(root: str) -> list[Path]:
    files = sorted(Path(root).glob(PYTHON_GLOB))
    # skip venv / __pycache__ / test files
    files = [
        f for f in files
        if not any(p in f.parts for p in ("venv", ".venv", "__pycache__", "node_modules"))
        and f.stat().st_size < MAX_FILE_SIZE_KB * 1024
    ]
    return files[:MAX_FILES]


async def _scan_file(fpath: Path, rel_path: str) -> dict | None:
    code = fpath.read_text(errors="replace")
    if not code.strip():
        return None

    semgrep_out = run_semgrep(code, "python")
    findings = semgrep_out.get("findings", [])
    if not findings:
        return None

    ai = await explain_vulnerabilities(code, findings)
    vulns = ai.get("vulnerabilities", [])
    if not vulns:
        return None

    return {
        "file": rel_path,
        "vulnerabilities": vulns,
        "risk_score": ai.get("risk_score", 0),
    }


def _aggregate(file_results: list[dict], all_files: list[Path]) -> dict:
    total_vulns = sum(len(f["vulnerabilities"]) for f in file_results)
    avg_risk = (
        sum(f["risk_score"] for f in file_results) / len(file_results)
        if file_results else 0
    )
    return {
        "files_scanned": len(all_files),
        "files_with_issues": len(file_results),
        "total_vulnerabilities": total_vulns,
        "average_risk_score": round(avg_risk),
        "results": file_results,
    }


def _progress(cb, pct: int, msg: str):
    if cb:
        cb(pct, msg)

"""
services/dep_scanner.py
Parses requirements.txt / pyproject.toml and queries OSV.dev for CVEs.
No API key required — OSV is free and open.
"""
import re
import httpx
import asyncio
from typing import Optional


OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"

SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MODERATE": "MEDIUM",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
}


# ── Parsers ────────────────────────────────────────────────────────────────

def parse_requirements_txt(content: str) -> list[dict]:
    """Return list of {name, version} from requirements.txt."""
    deps = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # match name==version or name>=version etc.
        m = re.match(r"^([A-Za-z0-9_\-\.]+)\s*[=<>!~]+\s*([^\s,;]+)", line)
        if m:
            deps.append({"name": m.group(1), "version": m.group(2)})
        else:
            # bare package name with no version pin
            m2 = re.match(r"^([A-Za-z0-9_\-\.]+)", line)
            if m2:
                deps.append({"name": m2.group(1), "version": None})
    return deps


def parse_pyproject_toml(content: str) -> list[dict]:
    """Rough TOML parser for [project] dependencies."""
    deps = []
    in_deps = False
    for line in content.splitlines():
        line = line.strip()
        if line == "[project]":
            in_deps = False
        if line == "dependencies = [" or line.startswith("dependencies=["):
            in_deps = True
            continue
        if in_deps:
            if line == "]":
                in_deps = False
                continue
            clean = line.strip('",\' ')
            m = re.match(r"^([A-Za-z0-9_\-\.]+)\s*[=<>!~]+\s*([^\s,;\"\']+)", clean)
            if m:
                deps.append({"name": m.group(1), "version": m.group(2)})
    return deps


# ── OSV query ──────────────────────────────────────────────────────────────

async def check_dependencies(deps: list[dict]) -> list[dict]:
    """
    Query OSV.dev batch API and return enriched deps with CVE info.
    """
    if not deps:
        return []

    queries = [
        {
            "version": d["version"] or "",
            "package": {"name": d["name"], "ecosystem": "PyPI"},
        }
        for d in deps
    ]

    async with httpx.AsyncClient(timeout=20) as client:
        resp = await client.post(OSV_BATCH_URL, json={"queries": queries})
        resp.raise_for_status()
        data = resp.json()

    results = []
    for dep, osv_result in zip(deps, data.get("results", [])):
        vulns = osv_result.get("vulns", [])
        if not vulns:
            results.append({**dep, "status": "safe", "vulns": []})
            continue

        enriched_vulns = [_summarise_vuln(v) for v in vulns]
        severity = _worst_severity(enriched_vulns)
        results.append({
            **dep,
            "status": "vulnerable",
            "severity": severity,
            "vulns": enriched_vulns,
        })

    return results


def _summarise_vuln(v: dict) -> dict:
    aliases = v.get("aliases", [])
    cve = next((a for a in aliases if a.startswith("CVE-")), v.get("id", ""))
    severity = "UNKNOWN"
    score = None
    for s in v.get("severity", []):
        if s.get("type") == "CVSS_V3":
            score = float(s.get("score", 0))
            if score >= 9.0:   severity = "CRITICAL"
            elif score >= 7.0: severity = "HIGH"
            elif score >= 4.0: severity = "MEDIUM"
            else:              severity = "LOW"
    return {
        "cve": cve,
        "summary": v.get("summary", "")[:120],
        "severity": severity,
        "cvss_score": score,
        "fixed_version": _extract_fix(v),
    }


def _extract_fix(v: dict) -> Optional[str]:
    for affected in v.get("affected", []):
        for r in affected.get("ranges", []):
            for event in r.get("events", []):
                if "fixed" in event:
                    return event["fixed"]
    return None


def _worst_severity(vulns: list[dict]) -> str:
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
    found = {v["severity"] for v in vulns}
    for s in order:
        if s in found:
            return s
    return "UNKNOWN"

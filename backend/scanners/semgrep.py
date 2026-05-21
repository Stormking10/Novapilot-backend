"""
scanners/semgrep.py
Runs Semgrep against a code snippet and returns normalised findings.
Semgrep must be installed: pip install semgrep
"""
import json
import subprocess
import tempfile
import os
from pathlib import Path


SEMGREP_RULES = {
    "python": [
        "p/python",
        "p/owasp-top-ten",
        "p/sql-injection",
    ],
    "javascript": [
        "p/javascript",
        "p/react",
        "p/typescript",
    ],
    "typescript": [
        "p/typescript",
        "p/react",
    ],
    "go": [
        "p/golang",
    ],
    "java": [
        "p/java",
    ],
    "csharp": [
        "p/csharp",
    ]
}

SEVERITY_MAP = {
    "ERROR":   "HIGH",
    "WARNING": "MEDIUM",
    "INFO":    "LOW",
}


def run_semgrep(code: str, language: str = "python") -> dict:
    """
    Write code to a temp file, run Semgrep, return parsed JSON output.
    Returns {"findings": [...], "raw": {...}}
    """
    ext_map = {
        "python": ".py",
        "javascript": ".js",
        "typescript": ".ts",
        "go": ".go",
        "java": ".java",
        "csharp": ".cs"
    }
    ext = ext_map.get(language, f".{language}")

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=ext, delete=False, encoding="utf-8"
    ) as f:
        f.write(code)
        tmp_path = f.name

    try:
        rules = SEMGREP_RULES.get(language, ["p/default"])
        rule_args = []
        for r in rules:
            rule_args += ["--config", r]

        cmd = [
            "semgrep",
            *rule_args,
            "--json",
            "--quiet",
            tmp_path,
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )

        raw = json.loads(result.stdout) if result.stdout else {}
        findings = _normalise(raw, tmp_path)
        return {"findings": findings, "raw": raw}

    except FileNotFoundError:
        # Semgrep not installed — return empty (AI will still analyse)
        return {"findings": [], "raw": {}, "error": "semgrep_not_installed"}
    except subprocess.TimeoutExpired:
        return {"findings": [], "raw": {}, "error": "semgrep_timeout"}
    finally:
        os.unlink(tmp_path)


def _normalise(raw: dict, tmp_path: str) -> list[dict]:
    """
    Convert Semgrep JSON results into a flat list of dicts.
    """
    findings = []
    for r in raw.get("results", []):
        findings.append({
            "rule_id":  r.get("check_id", "unknown"),
            "message":  r.get("extra", {}).get("message", ""),
            "severity": SEVERITY_MAP.get(
                r.get("extra", {}).get("severity", "INFO"), "INFO"
            ),
            "line":     str(r.get("start", {}).get("line", "?")),
            "owasp":    _extract_owasp(r),
            "cwe":      _extract_cwe(r),
        })
    return findings


def _extract_owasp(result: dict) -> str | None:
    metadata = result.get("extra", {}).get("metadata", {})
    owasp = metadata.get("owasp")
    if isinstance(owasp, list):
        return owasp[0] if owasp else None
    return owasp


def _extract_cwe(result: dict) -> str | None:
    metadata = result.get("extra", {}).get("metadata", {})
    cwe = metadata.get("cwe")
    if isinstance(cwe, list):
        return cwe[0] if cwe else None
    return cwe

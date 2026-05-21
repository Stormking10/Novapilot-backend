from pydantic import BaseModel
from typing import Optional
from enum import Enum
from datetime import datetime


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


class Language(str, Enum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    GO = "go"
    JAVA = "java"
    CSHARP = "csharp"


# ---------- Request ----------

class ScanRequest(BaseModel):
    code: str
    language: Language = Language.PYTHON
    filename: Optional[str] = "snippet.py"


# ---------- Inner models ----------

class Vulnerability(BaseModel):
    id: str
    title: str
    severity: Severity
    line: str
    owasp: Optional[str] = None
    rule_id: Optional[str] = None        # Semgrep rule that fired
    explanation: str                     # AI-generated
    fix: str                             # AI-generated secure snippet
    cwe: Optional[str] = None


# ---------- Response ----------

class ScanResult(BaseModel):
    scan_id: str
    id: Optional[str] = None
    language: Language
    risk_score: int                      # 0–100
    summary: str
    vulnerabilities: list[Vulnerability]
    created_at: Optional[datetime] = None
    filename: Optional[str] = None
    scanner_output: Optional[dict] = None  # raw Semgrep JSON (debug)

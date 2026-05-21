# OWASPilot — Backend

AI-powered Python vulnerability scanner. FastAPI + Semgrep + Claude/OpenAI.

## Quick start

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env        # add your ANTHROPIC_API_KEY or OPENAI_API_KEY
# then edit backend/.env and add your key like:
# ANTHROPIC_API_KEY=sk-...
# or OPENAI_API_KEY=sk-...
uvicorn main:app --reload
```

API is live at `http://localhost:8000`
Swagger docs at `http://localhost:8000/docs`

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/health` | Health check |
| POST | `/api/scan` | Scan code for vulnerabilities |
| GET | `/api/history` | Return past scan results |

## POST /api/scan

**Request**
```json
{
  "code": "import sqlite3\ndef get(u): ...",
  "language": "python",
  "filename": "app.py"
}
```

**Response**
```json
{
  "scan_id": "uuid",
  "language": "python",
  "risk_score": 85,
  "summary": "Critical SQL injection found.",
  "vulnerabilities": [
    {
      "id": "vuln-1",
      "title": "SQL Injection via f-string",
      "severity": "CRITICAL",
      "line": "7",
      "owasp": "A03:2021",
      "rule_id": "python.lang.security.audit.formatted-sql-query",
      "explanation": "...",
      "fix": "cursor.execute('SELECT * FROM users WHERE name = ?', (username,))",
      "cwe": "CWE-89"
    }
  ]
}
```

## Architecture

```
backend/
├── main.py               # FastAPI app + CORS
├── requirements.txt
├── .env.example
├── models/
│   └── scan.py           # Pydantic request/response models
├── scanners/
│   └── semgrep.py        # Semgrep wrapper + result normaliser
├── ai/
│   └── explainer.py      # LLM explanation engine (Anthropic / OpenAI)
├── routes/
│   ├── health.py
│   ├── scan.py           # POST /api/scan — main pipeline
│   └── history.py        # GET /api/history
└── services/             # (Phase 2) Supabase client, auth, etc.
```

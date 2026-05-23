# OWASPilot Backend

FastAPI backend for OWASPilot, an AI-assisted secure coding and vulnerability analysis API.

## Local Development

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements-dev.txt
uvicorn main:app --reload
```

The API runs at `http://localhost:8000`.

## Vercel

This repository includes Vercel entrypoints at both the repository root and inside `backend/`:

- `vercel.json`
- `api/index.py`
- `requirements.txt`
- `backend/vercel.json`
- `backend/api/index.py`
- `backend/requirements.txt`

The root deployment uses Vercel Services with the backend mounted at `/_/backend`.

## Main Endpoints

- `GET /api/health`
- `POST /api/scan`
- `GET /api/history`
- `POST /api/chat`
- `POST /api/assistant-chat`

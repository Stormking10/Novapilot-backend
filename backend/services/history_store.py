import json
import os
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock


def _history_file() -> Path:
    configured = os.getenv("OWASPILOT_HISTORY_FILE")
    if configured:
        return Path(configured)
    if os.getenv("VERCEL"):
        return Path("/tmp/owaspilot_scan_history.json")
    return Path(__file__).resolve().parents[1] / "data" / "scan_history.json"


HISTORY_FILE = _history_file()
MAX_HISTORY = 100
_LOCK = Lock()


def list_scans() -> list[dict]:
    with _LOCK:
        return list(reversed(_read_history()))


def save_scan(scan_result: dict) -> dict:
    record = _normalise_record(scan_result)
    with _LOCK:
        history = _read_history()
        history.append(record)
        history = history[-MAX_HISTORY:]
        _write_history(history)
    return record


def _normalise_record(scan_result: dict) -> dict:
    record = dict(scan_result)
    scan_id = record.get("scan_id") or record.get("id")
    record["scan_id"] = scan_id
    record["id"] = scan_id
    record.setdefault("created_at", datetime.now(timezone.utc).isoformat())
    return record


def _read_history() -> list[dict]:
    if not HISTORY_FILE.exists():
        return []
    try:
        data = json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []
    return data if isinstance(data, list) else []


def _write_history(history: list[dict]) -> None:
    HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
    HISTORY_FILE.write_text(
        json.dumps(history, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

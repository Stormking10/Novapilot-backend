from fastapi import APIRouter
from services.history_store import list_scans, save_scan


router = APIRouter()


@router.get("/history")
async def get_history():
    return {"scans": list_scans()}

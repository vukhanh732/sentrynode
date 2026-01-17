from fastapi import APIRouter
from pydantic import BaseModel
from typing import Any, Dict, List

router = APIRouter()

class LogBatch(BaseModel):
    agentid: str
    hostname: str
    events: List[Dict[str, Any]]

@router.post("/logs")
async def ingest_logs(payload: LogBatch):
    return {"status": "accepted", "eventcount": len(payload.events)}

from fastapi import APIRouter
from pydantic import BaseModel
from typing import Any, Dict, List

from app.services.detector import DetectionEngine

router = APIRouter()

# simple singleton for dev
engine = DetectionEngine(ssh_threshold=5, window_minutes=10, http_failure_threshold=20)

class LogBatch(BaseModel):
    agentid: str
    hostname: str
    events: List[Dict[str, Any]]

@router.post("/logs")
async def ingest_logs(payload: LogBatch):
    engine.process_events(payload.events)
    return {"status": "accepted", "eventcount": len(payload.events)}

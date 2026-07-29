from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.services.detector import DetectionEngine

router = APIRouter()

# simple singleton for dev
engine = DetectionEngine(ssh_threshold=5, window_minutes=10, http_failure_threshold=20)

MAX_BATCH_EVENTS = 500


class LogBatch(BaseModel):
    agentid: str
    hostname: str
    events: List[Dict[str, Any]]


@router.post("/logs")
async def ingest_logs(payload: LogBatch):
    if len(payload.events) > MAX_BATCH_EVENTS:
        raise HTTPException(
            status_code=413,
            detail=f"Batch too large: max {MAX_BATCH_EVENTS} events per request",
        )
    engine.process_events(payload.events)
    return {"status": "accepted", "eventcount": len(payload.events)}

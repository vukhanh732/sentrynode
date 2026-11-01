from typing import Any, Dict, List
import hmac
import sqlite3

from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel, field_validator

from app.limiter import limiter
from app.services.detector import DetectionEngine
from app.services.alert_store import AlertStore
from app.config import get_settings

router = APIRouter()

# simple singleton for dev
engine = DetectionEngine(
    ssh_threshold=5,
    window_minutes=10,
    http_failure_threshold=20,
    alert_store=AlertStore(get_settings().alert_db_path),
)

MAX_BATCH_EVENTS = 500


class LogBatch(BaseModel):
    agentid: str
    hostname: str
    events: List[Dict[str, Any]]

    @field_validator("events")
    @classmethod
    def validate_events(cls, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if len(events) > MAX_BATCH_EVENTS:
            # Keep the existing explicit 413 response in the route for oversized batches.
            return events
        for event in events:
            for key in ("source", "srcip", "eventtype", "httppath", "httpmethod"):
                value = event.get(key)
                if value is not None and (not isinstance(value, str) or len(value) > 2048):
                    raise ValueError(f"{key} must be a string of at most 2048 characters")
            status = event.get("httpstatus")
            if status is not None and (type(status) is not int or not 100 <= status <= 599):
                raise ValueError("httpstatus must be an HTTP status integer")
        return events


@router.post("/logs")
@limiter.limit("20/minute")
async def ingest_logs(
    request: Request, payload: LogBatch, x_agent_token: str = Header(default="", alias="X-Agent-Token")
):
    configured_token = get_settings().agent_token
    if not configured_token:
        raise HTTPException(status_code=503, detail="Agent ingestion is not configured")
    if not hmac.compare_digest(configured_token, x_agent_token):
        raise HTTPException(status_code=401, detail="Invalid agent token")
    if len(payload.events) > MAX_BATCH_EVENTS:
        raise HTTPException(
            status_code=413,
            detail=f"Batch too large: max {MAX_BATCH_EVENTS} events per request",
        )
    try:
        engine.process_events(payload.events)
    except sqlite3.Error as exc:
        raise HTTPException(status_code=503, detail="Alert storage unavailable") from exc
    return {"status": "accepted", "eventcount": len(payload.events)}

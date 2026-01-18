from fastapi import APIRouter
from app.api.routes.logs import engine

router = APIRouter()

@router.get("/alerts")
async def list_alerts():
    return {"alerts": engine.list_alerts()}

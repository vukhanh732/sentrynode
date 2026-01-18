from fastapi import APIRouter
from app.services.threatintel import ThreatIntelService

router = APIRouter()

@router.get("/threat-intel/{ip}")
async def get_threat_intel(ip: str):
    svc = ThreatIntelService()
    return await svc.check_ip(ip)

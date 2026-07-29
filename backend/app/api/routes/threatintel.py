import ipaddress

from fastapi import APIRouter, HTTPException, Request

from app.limiter import limiter
from app.services.threatintel import ThreatIntelService

router = APIRouter()


@router.get("/threat-intel/{ip}")
@limiter.limit("30/minute")
async def get_threat_intel(request: Request, ip: str):
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address")

    svc = ThreatIntelService()
    return await svc.check_ip(ip)

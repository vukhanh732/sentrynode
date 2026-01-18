from datetime import datetime

class ThreatIntelService:
    async def check_ip(self, ip: str):
        return {
            "ip": ip,
            "abuseConfidenceScore": 0,
            "totalReports": 0,
            "isMalicious": False,
            "source": "stub",
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }

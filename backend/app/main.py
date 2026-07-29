from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.api.routes.alerts import router as alerts_router
from app.api.routes.health import router as health_router
from app.api.routes.logs import engine, router as logs_router
from app.api.routes.threatintel import router as threatintel_router
from app.config import get_settings
from app.demo_seed import seed_demo_alerts
from app.limiter import limiter

settings = get_settings()

app = FastAPI(title="SentryNode API", version="0.1.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

if settings.corsorigins:
    origins = [o.strip() for o in settings.corsorigins.split(",") if o.strip()]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )

app.include_router(health_router)
app.include_router(logs_router, prefix="/api")
app.include_router(alerts_router, prefix="/api")
app.include_router(threatintel_router, prefix="/api")


@app.on_event("startup")
async def _seed_demo_data() -> None:
    if get_settings().demomode:
        seed_demo_alerts(engine)

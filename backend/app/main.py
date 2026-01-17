from fastapi import FastAPI
from app.api.routes.health import router as health_router
from app.api.routes.logs import router as logs_router
from app.api.routes.alerts import router as alerts_router

app = FastAPI(title="SentryNode API", version="0.1.0")

app.include_router(health_router)
app.include_router(logs_router, prefix="/api")
app.include_router(alerts_router, prefix="/api")

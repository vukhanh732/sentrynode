# SentryNode Public Showcase Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the real bugs and dead code found in SentryNode's backend, harden its two public endpoints for safe internet exposure, then deploy a live demo (Render) and a static showcase page (Netlify) so recruiters can see and use real, working evidence of the project.

**Architecture:** No new services or major components — this is a hardening pass on the existing FastAPI backend (config, threat-intel caching, rate limiting, CORS, health check, demo data seeding) followed by two deployment artifacts: a `render.yaml` blueprint for the backend and a single static HTML page for Netlify.

**Tech Stack:** FastAPI 0.104.1, Pydantic Settings, `redis.asyncio` (from the existing `redis==5.0.0` dependency), `slowapi` for rate limiting (new dependency), pytest for tests, plain HTML/CSS for the showcase page, Render (Docker Web Service) and Netlify (static site) for hosting.

## Global Constraints

- No new product features or detection rules — this plan is bug fixes, hardening, dead-code removal, and deployment only (per spec).
- No Windows installer/.exe (per spec — rejected as a mismatch for this project type).
- No public hosting of the full RabbitMQ/InfluxDB/Elasticsearch/Grafana stack (per spec) — the deployed demo runs as a single backend container.
- No authentication system added — rate limiting and payload caps are the agreed mitigation for the public demo (per spec).
- All existing unit tests in `backend/tests/unit` must keep passing after every task (run `pytest tests/unit -v` from `backend/` after each task's changes).
- Match the codebase's existing lowercase-field / uppercase-env-var naming convention in `app/config.py` (e.g. `loglevel` / `LOGLEVEL`).

---

## File Structure

**Created:**
- `backend/app/limiter.py` — shared `slowapi.Limiter` instance (avoids a circular import between `main.py` and the route modules).
- `backend/app/demo_seed.py` — seeds sample alerts into the detection engine when `DEMOMODE=true`.
- `backend/tests/unit/conftest.py` — autouse fixture resetting shared in-process state (detection engine, rate limiter, cached Redis client) before every test.
- `backend/tests/unit/test_threatintel_resilience.py` — Redis-outage graceful-degradation test.
- `backend/tests/unit/test_threatintel_validation.py` — invalid-IP rejection test.
- `backend/tests/unit/test_logs_batch_limit.py` — oversized-batch rejection test.
- `backend/tests/unit/test_rate_limiting.py` — rate-limit-triggers-429 tests.
- `backend/tests/unit/test_cors.py` — CORS header test.
- `backend/tests/unit/test_demo_seed.py` — demo-mode seeding test.
- `render.yaml` (repo root) — Render Blueprint for the backend Docker service.
- `showcase/index.html` — the Netlify static showcase page (self-contained, inline CSS, no build step).
- `showcase/netlify.toml` — Netlify publish config for the `showcase/` directory.

**Modified:**
- `backend/app/config.py` — add typed `redishost`, `redisport`, `redisdb`, `redisttlseconds`, `demomode`, `corsorigins` settings.
- `backend/app/services/threatintel.py` — async, cached, graceful-degradation Redis client.
- `backend/app/api/routes/threatintel.py` — IP validation + rate limiting.
- `backend/app/api/routes/logs.py` — batch size cap + rate limiting.
- `backend/app/api/routes/health.py` — reflect real Redis status.
- `backend/app/main.py` — CORS middleware, rate limiter wiring, demo-mode startup seeding.
- `backend/app/services/detector.py` — add a public `add_alert()` method (used by demo seeding instead of reaching into the private `_alerts` list).
- `backend/requirements.txt` — add `slowapi==0.1.10`.
- `backend/tests/unit/test_threatintel.py` — update mocks to `AsyncMock`.
- `backend/tests/unit/test_threatintel_cache.py` — update mocks to `AsyncMock`.
- `backend/tests/unit/test_health.py` — update expected response shape.
- `README.md` — correct the architecture section (implemented vs. roadmap), add a "Live Demo" section, update the configuration table.
- `.env.example` — add the new Redis/demo/CORS variables.

**Deleted:**
- `backend/app/services/elasticsearch_service.py` — dead code, never imported outside its own test.
- `backend/tests/unit/test_elasticsearch_service.py` — tests for the deleted service.
- `backend/app/tests/` — stray empty, untracked directory left over from earlier scaffolding.

---

### Task 1: Typed Redis/demo/CORS settings in config

**Files:**
- Modify: `backend/app/config.py`
- Test: `backend/tests/unit/test_config.py`

**Interfaces:**
- Produces: `Settings.redishost: str` (default `"localhost"`), `Settings.redisport: int` (default `6379`), `Settings.redisdb: int` (default `0`), `Settings.redisttlseconds: int` (default `3600`), `Settings.demomode: bool` (default `False`), `Settings.corsorigins: str` (default `""`, comma-separated list). All later tasks read these off `get_settings()`.

- [ ] **Step 1: Write the failing test**

Add to `backend/tests/unit/test_config.py`:

```python
def test_settings_new_fields_have_safe_defaults():
    get_settings.cache_clear()
    s = get_settings()
    assert s.redishost == "localhost"
    assert s.redisport == 6379
    assert s.redisdb == 0
    assert s.redisttlseconds == 3600
    assert s.demomode is False
    assert s.corsorigins == ""


def test_settings_new_fields_env_override(monkeypatch):
    get_settings.cache_clear()
    monkeypatch.setenv("REDISPORT", "6390")
    monkeypatch.setenv("DEMOMODE", "true")
    monkeypatch.setenv("CORSORIGINS", "https://example.netlify.app")
    s = get_settings()
    assert s.redisport == 6390
    assert s.demomode is True
    assert s.corsorigins == "https://example.netlify.app"
    get_settings.cache_clear()
```

- [ ] **Step 2: Run test to verify it fails**

Run (from `backend/`): `pytest tests/unit/test_config.py -v`
Expected: FAIL with `AttributeError: 'Settings' object has no attribute 'redishost'`

- [ ] **Step 3: Implement**

Replace the body of `backend/app/config.py` with:

```python
from functools import lru_cache
from typing import Optional
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    appname: str = "SentryNode"
    environment: str = "development"
    loglevel: str = "INFO"

    jwtsecret: str = "change-me"
    abuseipdbapikey: str = "change-me"
    discordwebhookurl: Optional[str] = None

    redishost: str = "localhost"
    redisport: int = 6379
    redisdb: int = 0
    redisttlseconds: int = 3600

    demomode: bool = False
    corsorigins: str = ""

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "allow"

@lru_cache
def get_settings() -> Settings:
    return Settings()

# Compatibility alias for existing imports
getsettings = get_settings
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/unit/test_config.py -v`
Expected: PASS (4 tests: the 2 existing + 2 new)

- [ ] **Step 5: Commit**

```bash
git add backend/app/config.py backend/tests/unit/test_config.py
git commit -m "feat(config): add typed redis/demo/cors settings"
```

---

### Task 2: Shared rate limiter module

**Files:**
- Create: `backend/app/limiter.py`

**Interfaces:**
- Produces: `limiter` (a `slowapi.Limiter` instance keyed by remote address). Task 7 wires it into `main.py` and decorates the two public routes with it; this task's file has no branching logic, so it is verified indirectly by Task 7's tests rather than a dedicated unit test.

- [ ] **Step 1: Add `slowapi` to dependencies**

In `backend/requirements.txt`, add this line after `redis==5.0.0`:

```
slowapi==0.1.10
```

Install it: `pip install -r backend/requirements.txt` (or `pip install slowapi==0.1.10` in your existing virtualenv).

- [ ] **Step 2: Create the limiter module**

Create `backend/app/limiter.py`:

```python
"""Shared rate limiter instance.

Lives in its own module (not main.py) so route modules can import it
without creating a circular import with app.main.
"""
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
```

- [ ] **Step 3: Commit**

```bash
git add backend/app/limiter.py backend/requirements.txt
git commit -m "feat(limiter): add shared slowapi limiter module"
```

---

### Task 3: Test isolation fixture for shared in-process state

**Files:**
- Create: `backend/tests/unit/conftest.py`

**Interfaces:**
- Consumes: `engine` from `app.api.routes.logs` (existing module-level `DetectionEngine` singleton), `limiter` from `app.limiter` (Task 2).
- Produces: an autouse pytest fixture that all tests in `backend/tests/unit` get automatically — no import needed in individual test files.

**Why this task exists:** `backend/app/api/routes/logs.py` holds a single module-level `DetectionEngine` instance shared by the whole test process (via `TestClient(app)`), and the rate limiter added in Task 2 will do the same. Without a reset between tests, one test's HTTP calls leak into the next test's assertions (already a latent risk today, and Task 7's rate-limit tests would otherwise permanently exhaust the limit for the rest of the test session).

- [ ] **Step 1: Create the fixture**

Create `backend/tests/unit/conftest.py`:

```python
import pytest

from app.api.routes.logs import engine
from app.limiter import limiter


@pytest.fixture(autouse=True)
def reset_shared_state():
    """Reset the module-level DetectionEngine and rate limiter before each test."""
    engine.clear_alerts()
    engine._failed_ssh_by_ip.clear()
    engine._http_failures_by_ip.clear()
    limiter.reset()
    yield
```

- [ ] **Step 2: Run the full unit suite to verify nothing broke**

Run (from `backend/`): `pytest tests/unit -v`
Expected: PASS, same test count as before this task (this fixture only resets state that already existed; it doesn't change behavior yet since nothing depends on the reset until later tasks).

- [ ] **Step 3: Commit**

```bash
git add backend/tests/unit/conftest.py
git commit -m "test: reset shared engine/limiter state between unit tests"
```

---

### Task 4: Fix ThreatIntelService — async, cached client, graceful Redis degradation

**Files:**
- Modify: `backend/app/services/threatintel.py`
- Modify: `backend/tests/unit/test_threatintel.py`
- Modify: `backend/tests/unit/test_threatintel_cache.py`
- Modify: `backend/tests/unit/conftest.py`
- Test: `backend/tests/unit/test_threatintel_resilience.py`

**Interfaces:**
- Produces: `get_redis_client() -> redis.asyncio.Redis` (module-level, `@lru_cache`'d singleton in `app.services.threatintel`), `ThreatIntelService.check_ip(ip: str) -> dict` (unchanged signature, now resilient to Redis being unreachable). Task 5 and Task 9 both call `get_redis_client()`.

**Bug being fixed:** the current code creates a brand-new `redis.Redis(...)` connection on every request and has no error handling — if Redis is unreachable, `check_ip()` raises an unhandled exception instead of returning a response.

- [ ] **Step 1: Write the failing test**

Create `backend/tests/unit/test_threatintel_resilience.py`:

```python
from unittest.mock import patch, MagicMock, AsyncMock

from fastapi.testclient import TestClient
from redis.exceptions import ConnectionError as RedisConnectionError

from app.main import app
from app.services.threatintel import get_redis_client


def test_threat_intel_survives_redis_outage():
    get_redis_client.cache_clear()
    with patch("app.services.threatintel.redis.Redis") as mock_redis:
        mock_instance = MagicMock()
        mock_instance.get = AsyncMock(side_effect=RedisConnectionError("connection refused"))
        mock_instance.setex = AsyncMock(side_effect=RedisConnectionError("connection refused"))
        mock_redis.return_value = mock_instance

        client = TestClient(app)
        r = client.get("/api/threat-intel/8.8.8.8")

        assert r.status_code == 200
        assert r.json()["ip"] == "8.8.8.8"
    get_redis_client.cache_clear()
```

- [ ] **Step 2: Run test to verify it fails**

Run (from `backend/`): `pytest tests/unit/test_threatintel_resilience.py -v`
Expected: FAIL — the current synchronous, unguarded Redis client either raises inside the request (500 response) or the test errors because `app.services.threatintel.redis.Redis` refers to the sync `redis` module, not `redis.asyncio`, so the patched mock's `AsyncMock` methods are never awaited compatibly.

- [ ] **Step 3: Rewrite the service**

Replace the full contents of `backend/app/services/threatintel.py` with:

```python
import json
from datetime import datetime
from functools import lru_cache
from typing import Any, Dict, Optional

import httpx
import redis.asyncio as redis
from redis.exceptions import RedisError

from app.config import get_settings


@lru_cache
def get_redis_client() -> "redis.Redis":
    """Single shared Redis client, reused across requests instead of
    opening a new connection per call."""
    settings = get_settings()
    return redis.Redis(
        host=settings.redishost,
        port=settings.redisport,
        db=settings.redisdb,
        decode_responses=True,
    )


class ThreatIntelService:
    def __init__(self) -> None:
        self.config = get_settings()
        self.api_key = self.config.abuseipdbapikey
        self.ttl = self.config.redisttlseconds
        self.redis = get_redis_client()

    def _key(self, ip: str) -> str:
        return f"ti:{ip}"

    async def _get_cache(self, ip: str) -> Optional[Dict[str, Any]]:
        try:
            raw = await self.redis.get(self._key(ip))
        except RedisError:
            return None
        if not raw:
            return None
        data = json.loads(raw)
        data["cached"] = True
        return data

    async def _set_cache(self, ip: str, data: Dict[str, Any]) -> None:
        try:
            await self.redis.setex(self._key(ip), self.ttl, json.dumps(data))
        except RedisError:
            pass

    async def _fetch_abuseipdb(self, ip: str) -> Dict[str, Any]:
        """Call AbuseIPDB API v2 check endpoint."""
        if not self.api_key or self.api_key == "change-me":
            return {
                "ip": ip,
                "abuseConfidenceScore": 0,
                "totalReports": 0,
                "isMalicious": False,
                "source": "default (no API key)",
                "timestamp": datetime.utcnow().isoformat() + "Z",
            }

        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": self.api_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}

        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(url, headers=headers, params=params)
                resp.raise_for_status()
                body = resp.json()

            data = body.get("data", {})
            score = data.get("abuseConfidenceScore", 0)

            return {
                "ip": ip,
                "abuseConfidenceScore": score,
                "totalReports": data.get("totalReports", 0),
                "isMalicious": score >= 50,
                "source": "abuseipdb",
                "timestamp": datetime.utcnow().isoformat() + "Z",
            }

        except (httpx.HTTPError, KeyError, ValueError) as e:
            return {
                "ip": ip,
                "abuseConfidenceScore": 0,
                "totalReports": 0,
                "isMalicious": False,
                "source": f"error: {type(e).__name__}",
                "timestamp": datetime.utcnow().isoformat() + "Z",
            }

    async def check_ip(self, ip: str) -> Dict[str, Any]:
        cached = await self._get_cache(ip)
        if cached:
            return cached

        data = await self._fetch_abuseipdb(ip)
        data["cached"] = False

        await self._set_cache(ip, data)
        return data
```

- [ ] **Step 4: Update the two existing tests to async-compatible mocks**

Replace the full contents of `backend/tests/unit/test_threatintel.py`:

```python
from unittest.mock import patch, MagicMock, AsyncMock

from fastapi.testclient import TestClient

from app.main import app
from app.services.threatintel import get_redis_client


def test_threat_intel_stub():
    get_redis_client.cache_clear()
    with patch("app.services.threatintel.redis.Redis") as mock_redis:
        mock_instance = MagicMock()
        mock_instance.get = AsyncMock(return_value=None)
        mock_redis.return_value = mock_instance

        client = TestClient(app)
        r = client.get("/api/threat-intel/1.2.3.4")
        assert r.status_code == 200
        data = r.json()
        assert data["ip"] == "1.2.3.4"
        assert data["source"] in ("stub", "placeholder", "default (no API key)")
    get_redis_client.cache_clear()
```

Replace the full contents of `backend/tests/unit/test_threatintel_cache.py`:

```python
from unittest.mock import patch, MagicMock, AsyncMock

from fastapi.testclient import TestClient

from app.main import app
from app.services.threatintel import get_redis_client


def test_threat_intel_sets_cached_flag_on_second_call():
    get_redis_client.cache_clear()
    with patch("app.services.threatintel.redis.Redis") as mock_redis:
        mock_instance = MagicMock()
        cache = {}

        async def mock_get(key):
            return cache.get(key)

        async def mock_setex(key, ttl, value):
            cache[key] = value

        mock_instance.get = AsyncMock(side_effect=mock_get)
        mock_instance.setex = AsyncMock(side_effect=mock_setex)
        mock_redis.return_value = mock_instance

        client = TestClient(app)

        r1 = client.get("/api/threat-intel/9.9.9.9")
        assert r1.status_code == 200
        assert r1.json().get("cached") is False

        r2 = client.get("/api/threat-intel/9.9.9.9")
        assert r2.status_code == 200
        assert r2.json().get("cached") is True
    get_redis_client.cache_clear()
```

- [ ] **Step 5: Extend the shared-state fixture to also clear the cached Redis client**

In `backend/tests/unit/conftest.py`, add the import and one line to the fixture so mocked Redis clients from one test never leak into another:

```python
import pytest

from app.api.routes.logs import engine
from app.limiter import limiter
from app.services.threatintel import get_redis_client


@pytest.fixture(autouse=True)
def reset_shared_state():
    """Reset the module-level DetectionEngine, rate limiter, and cached
    Redis client before each test."""
    engine.clear_alerts()
    engine._failed_ssh_by_ip.clear()
    engine._http_failures_by_ip.clear()
    limiter.reset()
    get_redis_client.cache_clear()
    yield
```

- [ ] **Step 6: Run the full unit suite to verify everything passes**

Run (from `backend/`): `pytest tests/unit -v`
Expected: PASS, all tests including the new resilience test.

- [ ] **Step 7: Commit**

```bash
git add backend/app/services/threatintel.py backend/tests/unit/test_threatintel.py backend/tests/unit/test_threatintel_cache.py backend/tests/unit/test_threatintel_resilience.py backend/tests/unit/conftest.py
git commit -m "fix(threatintel): reuse async redis client and degrade gracefully on outage"
```

---

### Task 5: Reject invalid IPs on the threat-intel endpoint

**Files:**
- Modify: `backend/app/api/routes/threatintel.py`
- Test: `backend/tests/unit/test_threatintel_validation.py`

**Interfaces:**
- Consumes: `ThreatIntelService` from Task 4 (unchanged usage).

- [ ] **Step 1: Write the failing test**

Create `backend/tests/unit/test_threatintel_validation.py`:

```python
from fastapi.testclient import TestClient

from app.main import app


def test_threat_intel_rejects_invalid_ip():
    client = TestClient(app)
    r = client.get("/api/threat-intel/not-an-ip")
    assert r.status_code == 400


def test_threat_intel_accepts_valid_ipv4():
    client = TestClient(app)
    r = client.get("/api/threat-intel/1.2.3.4")
    assert r.status_code == 200
```

- [ ] **Step 2: Run test to verify it fails**

Run (from `backend/`): `pytest tests/unit/test_threatintel_validation.py -v`
Expected: FAIL on `test_threat_intel_rejects_invalid_ip` — currently returns 200 for any string.

- [ ] **Step 3: Implement validation**

Replace the full contents of `backend/app/api/routes/threatintel.py`:

```python
import ipaddress

from fastapi import APIRouter, HTTPException

from app.services.threatintel import ThreatIntelService

router = APIRouter()


@router.get("/threat-intel/{ip}")
async def get_threat_intel(ip: str):
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address")

    svc = ThreatIntelService()
    return await svc.check_ip(ip)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/unit/test_threatintel_validation.py -v`
Expected: PASS

- [ ] **Step 5: Run the full unit suite**

Run: `pytest tests/unit -v`
Expected: PASS (all tests)

- [ ] **Step 6: Commit**

```bash
git add backend/app/api/routes/threatintel.py backend/tests/unit/test_threatintel_validation.py
git commit -m "feat(threatintel): validate ip path parameter"
```

---

### Task 6: Cap log batch size

**Files:**
- Modify: `backend/app/api/routes/logs.py`
- Test: `backend/tests/unit/test_logs_batch_limit.py`

**Interfaces:**
- Produces: `MAX_BATCH_EVENTS = 500` (module constant in `app.api.routes.logs`).

- [ ] **Step 1: Write the failing test**

Create `backend/tests/unit/test_logs_batch_limit.py`:

```python
from fastapi.testclient import TestClient

from app.main import app


def test_logs_rejects_oversized_batch():
    client = TestClient(app)
    payload = {
        "agentid": "test-agent",
        "hostname": "webserver",
        "events": [{"source": "nginx", "httpstatus": 200}] * 501,
    }
    r = client.post("/api/logs", json=payload)
    assert r.status_code == 413


def test_logs_accepts_batch_at_limit():
    client = TestClient(app)
    payload = {
        "agentid": "test-agent",
        "hostname": "webserver",
        "events": [{"source": "nginx", "httpstatus": 200}] * 500,
    }
    r = client.post("/api/logs", json=payload)
    assert r.status_code == 200
```

- [ ] **Step 2: Run test to verify it fails**

Run (from `backend/`): `pytest tests/unit/test_logs_batch_limit.py -v`
Expected: FAIL on `test_logs_rejects_oversized_batch` — currently accepts any batch size.

- [ ] **Step 3: Implement the cap**

Replace the full contents of `backend/app/api/routes/logs.py`:

```python
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/unit/test_logs_batch_limit.py -v`
Expected: PASS

- [ ] **Step 5: Run the full unit suite**

Run: `pytest tests/unit -v`
Expected: PASS (all tests)

- [ ] **Step 6: Commit**

```bash
git add backend/app/api/routes/logs.py backend/tests/unit/test_logs_batch_limit.py
git commit -m "feat(logs): cap ingestion batch size at 500 events"
```

---

### Task 7: Rate limiting on the two public endpoints

**Files:**
- Modify: `backend/app/main.py`
- Modify: `backend/app/api/routes/logs.py`
- Modify: `backend/app/api/routes/threatintel.py`
- Test: `backend/tests/unit/test_rate_limiting.py`

**Interfaces:**
- Consumes: `limiter` from `app.limiter` (Task 2).

- [ ] **Step 1: Write the failing test**

Create `backend/tests/unit/test_rate_limiting.py`:

```python
from fastapi.testclient import TestClient

from app.main import app


def test_logs_endpoint_rate_limited():
    client = TestClient(app)
    payload = {"agentid": "test-agent", "hostname": "webserver", "events": []}
    statuses = [client.post("/api/logs", json=payload).status_code for _ in range(21)]
    assert statuses[-1] == 429
    assert statuses[0] == 200


def test_threat_intel_endpoint_rate_limited():
    client = TestClient(app)
    statuses = [client.get("/api/threat-intel/1.1.1.1").status_code for _ in range(31)]
    assert statuses[-1] == 429
    assert statuses[0] == 200
```

- [ ] **Step 2: Run test to verify it fails**

Run (from `backend/`): `pytest tests/unit/test_rate_limiting.py -v`
Expected: FAIL — both endpoints currently accept unlimited requests, so no 429 ever appears.

- [ ] **Step 3: Wire the limiter into main.py**

Replace the full contents of `backend/app/main.py`:

```python
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.api.routes.alerts import router as alerts_router
from app.api.routes.health import router as health_router
from app.api.routes.logs import router as logs_router
from app.api.routes.threatintel import router as threatintel_router
from app.config import get_settings
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
```

- [ ] **Step 4: Decorate the logs endpoint**

In `backend/app/api/routes/logs.py`, add the rate-limit decorator and `Request` parameter. Update the imports and the route function:

```python
from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from app.limiter import limiter
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
@limiter.limit("20/minute")
async def ingest_logs(request: Request, payload: LogBatch):
    if len(payload.events) > MAX_BATCH_EVENTS:
        raise HTTPException(
            status_code=413,
            detail=f"Batch too large: max {MAX_BATCH_EVENTS} events per request",
        )
    engine.process_events(payload.events)
    return {"status": "accepted", "eventcount": len(payload.events)}
```

- [ ] **Step 5: Decorate the threat-intel endpoint**

Replace the full contents of `backend/app/api/routes/threatintel.py`:

```python
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
```

- [ ] **Step 6: Run test to verify it passes**

Run: `pytest tests/unit/test_rate_limiting.py -v`
Expected: PASS

- [ ] **Step 7: Run the full unit suite**

Run: `pytest tests/unit -v`
Expected: PASS (all tests — the Task 3 `conftest.py` fixture resetting `limiter` before each test is what keeps the other tests from being affected by this one's 21/31 rapid requests)

- [ ] **Step 8: Commit**

```bash
git add backend/app/main.py backend/app/api/routes/logs.py backend/app/api/routes/threatintel.py backend/tests/unit/test_rate_limiting.py
git commit -m "feat(api): rate limit public log ingestion and threat-intel endpoints"
```

---

### Task 8: CORS test

**Files:**
- Test: `backend/tests/unit/test_cors.py`

**Interfaces:**
- Consumes: `settings.corsorigins` (Task 1), CORS middleware wiring (Task 7, already in `main.py`).

CORS middleware was already added in Task 7's `main.py` rewrite (config-gated). This task only adds the test proving it behaves correctly, since `main.py`'s `app` object is built once at import time from whatever `CORSORIGINS` is set when the test process starts — so the test must reload the module with the env var set.

- [ ] **Step 1: Write the test**

Create `backend/tests/unit/test_cors.py`:

```python
import importlib

from fastapi.testclient import TestClient


def test_cors_allows_configured_origin(monkeypatch):
    from app.config import get_settings

    get_settings.cache_clear()
    monkeypatch.setenv("CORSORIGINS", "https://sentrynode-demo.netlify.app")

    import app.main as main_module

    importlib.reload(main_module)

    client = TestClient(main_module.app)
    r = client.get(
        "/health",
        headers={"Origin": "https://sentrynode-demo.netlify.app"},
    )
    assert r.headers.get("access-control-allow-origin") == "https://sentrynode-demo.netlify.app"

    get_settings.cache_clear()
    monkeypatch.delenv("CORSORIGINS", raising=False)
    importlib.reload(main_module)
```

- [ ] **Step 2: Run the test**

Run (from `backend/`): `pytest tests/unit/test_cors.py -v`
Expected: PASS (Task 7 already implemented the CORS middleware; this step is verifying it, not implementing something new)

If it fails, check that `backend/app/main.py` matches the "Step 3 (corrected)" version from Task 7 exactly (the `if settings.corsorigins:` block must run at import time based on `get_settings()`).

- [ ] **Step 3: Run the full unit suite**

Run: `pytest tests/unit -v`
Expected: PASS. Note: because this test reloads `app.main`, confirm no other test file relies on `app.main`'s `app` object being the exact same Python object across the whole session (none do — every existing test constructs `TestClient(app)` fresh from the current import of `app.main.app`).

- [ ] **Step 4: Commit**

```bash
git add backend/tests/unit/test_cors.py
git commit -m "test(cors): verify configured origin is allowed"
```

---

### Task 9: Health check reflects real Redis status

**Files:**
- Modify: `backend/app/api/routes/health.py`
- Modify: `backend/tests/unit/test_health.py`

**Interfaces:**
- Consumes: `get_redis_client()` from `app.services.threatintel` (Task 4).

- [ ] **Step 1: Write the failing test**

Replace the full contents of `backend/tests/unit/test_health.py`:

```python
from fastapi.testclient import TestClient

from app.main import app


def test_health_reports_status_and_redis_field():
    client = TestClient(app)
    r = client.get("/health")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert data["redis"] in ("ok", "unavailable")
```

- [ ] **Step 2: Run test to verify it fails**

Run (from `backend/`): `pytest tests/unit/test_health.py -v`
Expected: FAIL — `KeyError: 'redis'`, current response is only `{"status": "ok"}`.

- [ ] **Step 3: Implement**

Replace the full contents of `backend/app/api/routes/health.py`:

```python
from fastapi import APIRouter
from redis.exceptions import RedisError

from app.services.threatintel import get_redis_client

router = APIRouter()


@router.get("/health")
async def health():
    redis_status = "ok"
    try:
        await get_redis_client().ping()
    except RedisError:
        redis_status = "unavailable"
    return {"status": "ok", "redis": redis_status}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/unit/test_health.py -v`
Expected: PASS (works whether or not a real Redis is reachable in the environment running the test, since both outcomes are asserted as acceptable)

- [ ] **Step 5: Run the full unit suite**

Run: `pytest tests/unit -v`
Expected: PASS (all tests)

- [ ] **Step 6: Commit**

```bash
git add backend/app/api/routes/health.py backend/tests/unit/test_health.py
git commit -m "fix(health): report real redis connectivity instead of a hardcoded status"
```

---

### Task 10: Demo-mode alert seeding

**Files:**
- Modify: `backend/app/services/detector.py`
- Modify: `backend/app/main.py`
- Create: `backend/app/demo_seed.py`
- Test: `backend/tests/unit/test_demo_seed.py`

**Interfaces:**
- Produces: `DetectionEngine.add_alert(alert: dict) -> None` (public method), `seed_demo_alerts(engine: DetectionEngine) -> None` (in `app.demo_seed`).

- [ ] **Step 1: Write the failing test**

Create `backend/tests/unit/test_demo_seed.py`:

```python
import importlib

from fastapi.testclient import TestClient


def test_demo_mode_seeds_sample_alerts(monkeypatch):
    from app.config import get_settings

    get_settings.cache_clear()
    monkeypatch.setenv("DEMOMODE", "true")

    import app.main as main_module

    importlib.reload(main_module)

    with TestClient(main_module.app) as client:
        alerts = client.get("/api/alerts").json()["alerts"]
        assert len(alerts) >= 3
        assert any(a["rule"] == "ssh_bruteforce" for a in alerts)
        assert any(a["rule"] == "sql_injection" for a in alerts)

    get_settings.cache_clear()
    monkeypatch.delenv("DEMOMODE", raising=False)
    importlib.reload(main_module)


def test_demo_mode_off_by_default():
    from app.api.routes.alerts import router  # noqa: F401  (ensures app import doesn't seed)
    from app.main import app

    with TestClient(app) as client:
        alerts = client.get("/api/alerts").json()["alerts"]
        assert alerts == []
```

- [ ] **Step 2: Run test to verify it fails**

Run (from `backend/`): `pytest tests/unit/test_demo_seed.py -v`
Expected: FAIL — no startup seeding exists yet.

- [ ] **Step 3: Add the public `add_alert` method to DetectionEngine**

In `backend/app/services/detector.py`, add this method right after `clear_alerts` (around line 325-327, just before `get_threat_score_for_ip`):

```python
    def add_alert(self, alert: Dict[str, Any]) -> None:
        """Append a pre-built alert (used for demo-data seeding)."""
        self._alerts.append(alert)
```

- [ ] **Step 4: Create the demo seed module**

Create `backend/app/demo_seed.py`:

```python
"""Seed the detection engine with sample alerts for demo mode."""
from datetime import datetime, timezone

from app.services.detector import DetectionEngine


def seed_demo_alerts(engine: DetectionEngine) -> None:
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    demo_alerts = [
        {
            "rule": "ssh_bruteforce",
            "srcip": "203.0.113.42",
            "failure_count": 6,
            "window_minutes": 10,
            "threat_level": "HIGH",
            "threat_score": 85,
            "message": "SSH brute force: 6 failed attempts from 203.0.113.42 in 10m",
            "timestamp": now,
        },
        {
            "rule": "sql_injection",
            "srcip": "198.51.100.23",
            "httpmethod": "GET",
            "httppath": "/products?id=1' OR '1'='1",
            "matched_patterns": ["' or '1'='1"],
            "threat_level": "CRITICAL",
            "threat_score": 95,
            "message": "SQL injection: 1 patterns matched in /products?id=1' or '1'='1",
            "timestamp": now,
        },
        {
            "rule": "path_traversal",
            "srcip": "192.0.2.77",
            "httpmethod": "GET",
            "httppath": "/static/../../etc/passwd",
            "matched_patterns": ["../"],
            "threat_level": "HIGH",
            "threat_score": 80,
            "message": "Path traversal: directory traversal attempts detected",
            "timestamp": now,
        },
    ]

    for alert in demo_alerts:
        engine.add_alert(dict(alert))
```

- [ ] **Step 5: Wire the startup hook into main.py**

Replace the full contents of `backend/app/main.py`:

```python
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
```

- [ ] **Step 6: Run test to verify it passes**

Run: `pytest tests/unit/test_demo_seed.py -v`
Expected: PASS

- [ ] **Step 7: Run the full unit suite**

Run: `pytest tests/unit -v`
Expected: PASS (all tests, including the pre-existing `test_alerts_empty_by_default` — demo mode stays off unless `DEMOMODE=true` is explicitly set)

- [ ] **Step 8: Commit**

```bash
git add backend/app/services/detector.py backend/app/demo_seed.py backend/app/main.py backend/tests/unit/test_demo_seed.py
git commit -m "feat(demo): seed sample alerts on startup when DEMOMODE is enabled"
```

---

### Task 11: Remove dead Elasticsearch code and fix stale docs

**Files:**
- Delete: `backend/app/services/elasticsearch_service.py`
- Delete: `backend/tests/unit/test_elasticsearch_service.py`
- Delete: `backend/app/tests/` (empty, untracked directory)
- Modify: `README.md`

**Why:** `ElasticsearchService` is fully built (indexing, search, timeline aggregation) but never imported by `main.py` or any route — grepping `backend/app/` confirms nothing outside its own test file references it. Shipping unused code with its own passing test suite creates a false impression of completeness in a project meant to be read by recruiters. The README's architecture diagram currently implies Elasticsearch/InfluxDB/RabbitMQ are active parts of the request path; they are not (confirmed: no `pika`/`influxdb` imports anywhere in `backend/app/`).

- [ ] **Step 1: Confirm nothing else references the service**

Run (from `backend/`): `grep -rn "ElasticsearchService\|elasticsearch_service" app/ tests/ --include=*.py`
Expected: only `app/services/elasticsearch_service.py` and `tests/unit/test_elasticsearch_service.py` themselves — no callers.

- [ ] **Step 2: Delete the dead files**

```bash
git rm backend/app/services/elasticsearch_service.py backend/tests/unit/test_elasticsearch_service.py
rm -rf backend/app/tests
```

- [ ] **Step 3: Run the full unit suite**

Run (from `backend/`): `pytest tests/unit -v`
Expected: PASS (fewer tests than before — the deleted file's tests are gone — but no failures, since nothing depended on `ElasticsearchService`)

- [ ] **Step 4: Correct the README architecture section**

In `README.md`, replace the block from `## Architecture` through the closing ` ``` ` (lines 25-59) with:

```markdown
## Architecture

**Implemented and running today:**

```
┌─────────────┐
│   Agents    │ (SSH logs, nginx logs, etc.)
└──────┬──────┘
       │ (HTTP POST /api/logs)
       ▼
┌─────────────────────────────────────┐
│    FastAPI Backend                  │
│  ┌──────────────────────────────┐   │
│  │  Detection Engine (in-memory)│   │
│  │  - SSH Brute Force           │   │
│  │  - SQL Injection             │   │
│  │  - Path Traversal            │   │
│  │  - HTTP Method Scanning      │   │
│  │  - HTTP Auth Brute Force     │   │
│  │  - Suspicious Path Access    │   │
│  └──────────────────────────────┘   │
│  ┌──────────────────────────────┐   │
│  │  Threat Intel Service        │   │
│  │  - AbuseIPDB Integration     │   │
│  │  - Redis Caching (optional,  │   │
│  │    degrades gracefully)      │   │
│  └──────────────────────────────┘   │
└──────────────┬───────────────────────┘
               ▼
            ┌───────┐
            │ Redis │ (cache only)
            └───────┘
```

**Provisioned in `docker-compose.yml` for local full-stack development, not yet wired into the request path:** RabbitMQ, InfluxDB, Elasticsearch, Grafana. These represent the intended direction (queued ingestion, long-term log storage, metrics dashboards) but the backend code doesn't call them yet — see the Roadmap section below. Being upfront about this split is deliberate: it's a mid-flight infrastructure project, not a finished platform.
```

- [ ] **Step 5: Update the Technology Stack and Roadmap sections for consistency**

In `README.md`, in the `## Technology Stack` section, change the `Infrastructure` bullet's sub-list to make the not-yet-wired-in status explicit:

Find:
```markdown
- **Infrastructure**: Docker Compose
  - RabbitMQ 3.12 (message queue)
  - Elasticsearch 8.11 (log indexing)
  - InfluxDB 2.7 (time-series metrics)
  - Grafana 10.2 (visualization)
  - Redis (caching)
```

Replace with:
```markdown
- **Infrastructure**: Docker Compose
  - Redis (caching — actively used)
  - RabbitMQ 3.12, Elasticsearch 8.11, InfluxDB 2.7, Grafana 10.2 — provisioned for local dev, not yet wired into the backend (see Roadmap)
```

- [ ] **Step 6: Commit**

```bash
git add -A README.md backend/app/services/elasticsearch_service.py backend/tests/unit/test_elasticsearch_service.py
git commit -m "chore: remove unused ElasticsearchService and correct architecture docs"
```

---

### Task 12: Render deployment config

**Files:**
- Create: `render.yaml`
- Modify: `.env.example`
- Modify: `README.md`

**Interfaces:**
- None (deployment configuration, no code interfaces).

- [ ] **Step 1: Create the Render blueprint**

Create `render.yaml` at the repo root:

```yaml
services:
  - type: web
    name: sentrynode-backend
    runtime: docker
    dockerfilePath: ./backend/Dockerfile
    dockerContext: ./backend
    plan: free
    healthCheckPath: /health
    envVars:
      - key: DEMOMODE
        value: "true"
      - key: CORSORIGINS
        value: ""
      - key: ABUSEIPDBAPIKEY
        sync: false
      - key: JWTSECRET
        generateValue: true
```

- [ ] **Step 2: Add the new variables to `.env.example`**

Append to `.env.example`:

```
REDISHOST=localhost
REDISPORT=6379
REDISDB=0
REDISTTLSECONDS=3600
DEMOMODE=false
CORSORIGINS=
```

- [ ] **Step 3: Deploy to Render**

This step is manual (Render account/dashboard action, not code):

1. Push the current branch to GitHub (`git push`).
2. In the Render dashboard, choose "New +" → "Blueprint", point it at this GitHub repo. Render reads `render.yaml` and provisions the `sentrynode-backend` web service.
3. When prompted for the `ABUSEIPDBAPIKEY` secret, either supply a real key or leave it blank — `ThreatIntelService` already falls back to a safe `"default (no API key)"` response either way (Task 4 confirmed this path is exercised and tested).
4. Wait for the first deploy to finish, then note the live URL Render assigns — it will be `https://sentrynode-backend.onrender.com` (or `https://sentrynode-backend-<random-suffix>.onrender.com` if that name is taken; the exact URL is shown at the top of the service's page in the Render dashboard immediately after deploy). Task 13 needs this exact URL.
5. Verify: `curl https://<your-render-url>/health` returns `{"status":"ok","redis":"unavailable"}` (no Redis is deployed alongside it, which is expected and handled gracefully per Task 4/9), and `curl https://<your-render-url>/api/alerts` returns the 3 seeded demo alerts from Task 10.

- [ ] **Step 4: Add a "Live Demo" section to the README**

In `README.md`, insert this new section immediately after the `**Status**` line (after line 5):

```markdown
## Live Demo

- **Try it live**: `https://<your-render-url>/docs` (replace with the URL noted in the deployment step — Swagger UI, fully interactive)
- **Alerts feed**: `https://<your-render-url>/api/alerts`

Running on Render's free tier: if it's been idle for ~15 minutes, the first request takes 30-60 seconds to wake up. Subsequent requests are fast. The demo runs in `DEMOMODE`, seeded with a few sample alerts, and has no persistent database — state resets on redeploy.
```

Replace `https://<your-render-url>` with the actual URL from Step 3 in both places before committing.

- [ ] **Step 5: Commit**

```bash
git add render.yaml .env.example README.md
git commit -m "feat(deploy): add render.yaml blueprint and live demo docs"
```

---

### Task 13: Netlify showcase page

**Files:**
- Create: `showcase/index.html`
- Create: `showcase/netlify.toml`

**Interfaces:**
- Consumes: the live Render URL from Task 12, Step 3; the GitHub repo URL `https://github.com/vukhanh732/sentrynode`.

- [ ] **Step 1: Create the Netlify publish config**

Create `showcase/netlify.toml`:

```toml
[build]
  publish = "."
```

- [ ] **Step 2: Create the showcase page**

Create `showcase/index.html`. Replace `RENDER_URL_HERE` (appears twice, in the two `href` attributes in the hero section) with the actual Render URL from Task 12 before deploying:

```html
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SentryNode — Home-built SIEM</title>
<style>
  :root {
    color-scheme: light dark;
    --bg: #0b0f14;
    --panel: #121821;
    --border: #232c38;
    --text: #e6edf3;
    --muted: #8b98a5;
    --accent: #4fd1c5;
    --danger: #f56565;
    --warn: #ecc94b;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    line-height: 1.6;
  }
  .wrap { max-width: 860px; margin: 0 auto; padding: 3rem 1.5rem 5rem; }
  header { text-align: center; margin-bottom: 3rem; }
  h1 { font-size: 2.2rem; margin: 0 0 0.5rem; }
  .tagline { color: var(--muted); font-size: 1.1rem; margin: 0 0 2rem; }
  .cta { display: flex; gap: 1rem; justify-content: center; flex-wrap: wrap; }
  .btn {
    display: inline-block;
    padding: 0.75rem 1.5rem;
    border-radius: 8px;
    text-decoration: none;
    font-weight: 600;
    border: 1px solid var(--border);
  }
  .btn.primary { background: var(--accent); color: #06201d; border-color: var(--accent); }
  .btn.secondary { color: var(--text); }
  section { margin-bottom: 3rem; }
  h2 { font-size: 1.4rem; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem; }
  .card { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 1.25rem; }
  .card h3 { margin: 0 0 0.5rem; font-size: 1rem; }
  .card p { margin: 0; color: var(--muted); font-size: 0.92rem; }
  .badge { display: inline-block; font-size: 0.72rem; padding: 0.15rem 0.5rem; border-radius: 999px; margin-left: 0.4rem; vertical-align: middle; }
  .badge.live { background: rgba(79,209,197,0.15); color: var(--accent); }
  .badge.roadmap { background: rgba(236,201,75,0.15); color: var(--warn); }
  pre {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 1rem;
    overflow-x: auto;
    font-size: 0.85rem;
  }
  code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  footer { text-align: center; color: var(--muted); font-size: 0.85rem; }
  a { color: var(--accent); }
</style>
</head>
<body>
<div class="wrap">

  <header>
    <h1>SentryNode</h1>
    <p class="tagline">A home-built SIEM: log ingestion, real-time threat detection, and threat-intel enrichment — built solo from scratch.</p>
    <div class="cta">
      <a class="btn primary" href="RENDER_URL_HERE/docs">Try it live (Swagger UI)</a>
      <a class="btn secondary" href="https://github.com/vukhanh732/sentrynode">View source on GitHub</a>
    </div>
  </header>

  <section>
    <h2>What it does</h2>
    <div class="grid">
      <div class="card">
        <h3>Detects attacks in real time <span class="badge live">live</span></h3>
        <p>SSH brute force, SQL injection, path traversal, HTTP method scanning, auth brute force, and suspicious path access — all detected from streamed log events.</p>
      </div>
      <div class="card">
        <h3>Enriches with threat intel <span class="badge live">live</span></h3>
        <p>Looks up IP reputation via AbuseIPDB, with Redis-backed caching that degrades gracefully if the cache is unavailable.</p>
      </div>
      <div class="card">
        <h3>Full SIEM pipeline <span class="badge roadmap">roadmap</span></h3>
        <p>Docker Compose also provisions Elasticsearch, InfluxDB, RabbitMQ, and Grafana for long-term storage, metrics, and dashboards — designed for, not yet wired into, the live request path.</p>
      </div>
    </div>
  </section>

  <section>
    <h2>See it work</h2>
    <p>Post a batch of log events and watch an alert come back:</p>
    <pre><code>curl -X POST RENDER_URL_HERE/api/logs \
  -H "Content-Type: application/json" \
  -d '{
    "agentid": "demo-agent",
    "hostname": "web-01",
    "events": [
      {"source": "ssh", "eventtype": "Failed password", "srcip": "203.0.113.9"},
      {"source": "ssh", "eventtype": "Failed password", "srcip": "203.0.113.9"},
      {"source": "ssh", "eventtype": "Failed password", "srcip": "203.0.113.9"},
      {"source": "ssh", "eventtype": "Failed password", "srcip": "203.0.113.9"},
      {"source": "ssh", "eventtype": "Failed password", "srcip": "203.0.113.9"}
    ]
  }'

curl RENDER_URL_HERE/api/alerts
# → includes a freshly generated "ssh_bruteforce" alert for 203.0.113.9</code></pre>
    <p style="color:var(--muted); font-size:0.85rem;">Running on a free-tier host: the first request after ~15 minutes idle can take 30-60 seconds to wake up.</p>
  </section>

  <section>
    <h2>Why it's built this way</h2>
    <p>This project intentionally separates what's implemented from what's planned. The detection engine and threat-intel service are real, tested, and running behind the "Try it live" link above. Elasticsearch/InfluxDB/RabbitMQ/Grafana are part of the target architecture and run locally via Docker Compose, but aren't yet in the live request path — that's the next phase, not a hidden gap.</p>
  </section>

  <footer>
    <p>Built by Vu Khanh Luu · <a href="https://github.com/vukhanh732/sentrynode">github.com/vukhanh732/sentrynode</a></p>
  </footer>

</div>
</body>
</html>
```

- [ ] **Step 3: Substitute the real Render URL**

Replace both occurrences of `RENDER_URL_HERE` in `showcase/index.html` with the actual URL from Task 12, Step 3 (e.g. `https://sentrynode-backend.onrender.com`).

- [ ] **Step 4: Deploy to Netlify**

Manual step (Netlify account/dashboard action, not code):

1. In the Netlify dashboard, "Add new site" → "Import an existing project" → connect the GitHub repo.
2. Set "Base directory" to `showcase` and leave the build command empty (it's a static file, no build step).
3. Deploy. Netlify assigns a URL like `https://sentrynode-<random>.netlify.app` — optionally rename it in Site settings → Domain management for a cleaner URL (e.g. `sentrynode-vukhanh.netlify.app`).
4. Verify the page loads, and that the "Try it live" button opens the Render-hosted Swagger UI.

- [ ] **Step 5: Commit**

```bash
git add showcase/
git commit -m "feat(showcase): add static Netlify landing page"
```

---

### Task 14: Final verification

**Files:** none (verification only).

- [ ] **Step 1: Run the full unit test suite**

Run (from `backend/`): `pytest tests/unit -v --cov=app --cov-report=term`
Expected: PASS, all tests green.

- [ ] **Step 2: Run the same lint checks CI runs**

Run (from `backend/`):
```bash
flake8 app --count --select=E9,F63,F7,F82 --show-source --statistics
black app --check --line-length=120
```
Expected: no output from flake8 (no syntax errors/undefined names), and black reports no reformatting needed. If black wants changes, run `black app --line-length=120` to apply them, then re-run the unit suite to confirm nothing broke, and commit the formatting fix separately.

- [ ] **Step 3: Manual smoke test against the deployed demo**

```bash
curl https://<your-render-url>/health
curl https://<your-render-url>/api/alerts
curl https://<your-render-url>/api/threat-intel/8.8.8.8
```
Expected: all three return 200 with the shapes described in the README's API Endpoints section.

- [ ] **Step 4: Manual check of the Netlify page**

Open the Netlify URL in a browser, confirm the page renders correctly in both light and dark OS theme (the page uses `color-scheme: light dark` and CSS variables so it should adapt automatically), and click "Try it live" to confirm it opens the live Swagger UI.

- [ ] **Step 5: Commit any final fixes**

If Steps 2-4 surfaced anything to fix, make the fix, re-run the relevant verification, and commit with a message describing what was fixed. If nothing needed fixing, no commit is needed for this task.

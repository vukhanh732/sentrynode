# SentryNode

A lightweight, home-built Security Information and Event Management (SIEM) system for detecting, alerting, and analyzing security threats. SentryNode ingests logs from distributed agents, applies detection rules, correlates threat intelligence, and visualizes security metrics.

**Status**: Phase 1 - Core detection and threat intel features, hardened and deployed as a live demo

## Live Demo

- **Try it live**: [sentrynode-backend.onrender.com/docs](https://sentrynode-backend.onrender.com/docs) (Swagger UI, fully interactive)
- **Alerts feed**: [sentrynode-backend.onrender.com/api/alerts](https://sentrynode-backend.onrender.com/api/alerts)

Running on Render's free tier: if it's been idle for ~15 minutes, the first request takes 30-60 seconds to wake up. Subsequent requests are fast. The demo runs in `DEMOMODE`, seeded with a few sample alerts, and has no persistent database — state resets on redeploy.

## Features

### 🔍 Threat Detection
- **SSH Brute Force Detection** - Identifies suspicious patterns of failed SSH login attempts from the same source IP within a configurable time window
- **SQL Injection Detection** - Pattern-based detection of SQL injection attempts in HTTP requests

### 🌐 Threat Intelligence
- **IP Reputation Checking** - Integrates with AbuseIPDB API to check IP maliciousness scores
- **Response Caching** - Redis-backed caching with configurable TTL to reduce API calls

### 📊 Log Ingestion & Management
- **Batch Log Ingestion API** - Accepts structured log events from agents (SSH, nginx, etc.)
- **Alert Generation** - Automatically generates alerts with severity levels (HIGH, CRITICAL)
- **Alert Retrieval** - Query generated alerts via REST API

### 🏥 System Health
- **Health Check Endpoint** - Monitor API and dependency status

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

## Quick Start

### Prerequisites
- Docker & Docker Compose
- Git

### Setup (5 minutes)

1. **Clone and configure**
   ```bash
   cd sentrynode
   cp .env.example .env
   ```

2. **Start all services**
   ```bash
   docker compose up -d --build
   ```

3. **Verify health**
   ```bash
   curl http://localhost:8000/health
   ```
   Expected: `{"status":"ok","redis":"ok"}` (the `redis` field reports `"unavailable"` if the cache can't be reached, but the endpoint still returns 200)

### Access Services

| Service | URL | Credentials |
|---------|-----|-------------|
| **SentryNode API** | http://localhost:8000 | - |
| **Grafana** | http://localhost:3000 | admin / admin |
| **RabbitMQ** | http://localhost:15672 | guest / guest |
| **Elasticsearch** | http://localhost:9200 | - |
| **InfluxDB** | http://localhost:8086 | admin / password123 |

**📄 API Docs**: http://localhost:8000/docs (auto-generated Swagger UI)

## API Endpoints

### Health Check
```bash
GET /health
```
Returns API status. `redis` reports `"ok"` or `"unavailable"` depending on whether the cache backend can be reached (the endpoint itself still returns 200 either way):
```json
{
  "status": "ok",
  "redis": "ok"
}
```

### Log Ingestion
```bash
POST /api/logs
Content-Type: application/json

{
  "agentid": "agent-001",
  "hostname": "web-server-01",
  "events": [
    {
      "source": "ssh",
      "eventtype": "Failed password",
      "srcip": "192.168.1.100",
      "timestamp": "2024-01-15T10:30:00Z"
    },
    {
      "source": "nginx",
      "httpmethod": "GET",
      "httppath": "/api/users' OR '1'='1",
      "srcip": "10.0.0.50",
      "timestamp": "2024-01-15T10:31:00Z"
    }
  ]
}
```

Rate-limited to **20 requests/minute** per client (returns `429` when exceeded). Batches are capped at **500 events** per request (returns `413` if exceeded).

**Response**: 
```json
{
  "status": "accepted",
  "eventcount": 2
}
```

### List Alerts
```bash
GET /api/alerts
```

**Response**:
```json
{
  "alerts": [
    {
      "rule": "ssh_bruteforce",
      "srcip": "192.168.1.100",
      "failure_count": 5,
      "window_minutes": 10,
      "threatlevel": "HIGH",
      "message": "SSH brute force suspected from 192.168.1.100",
      "timestamp": "2024-01-15T10:35:00Z"
    },
    {
      "rule": "sql_injection",
      "srcip": "10.0.0.50",
      "httpmethod": "GET",
      "httppath": "/api/users' OR '1'='1",
      "matched_patterns": ["' or '1'='1"],
      "threatlevel": "CRITICAL",
      "message": "Potential SQL injection detected",
      "timestamp": "2024-01-15T10:31:00Z"
    }
  ]
}
```

### Threat Intelligence Lookup
```bash
GET /api/threat-intel/{ip}
```

Rate-limited to **30 requests/minute** per client (returns `429` when exceeded). The `{ip}` path parameter is validated as a real IP address; an invalid value returns `400`.

**Response**:
```json
{
  "ip": "192.168.1.100",
  "abuseConfidenceScore": 75,
  "totalReports": 12,
  "isMalicious": true,
  "source": "abuseipdb",
  "cached": false,
  "timestamp": "2024-01-15T10:32:00Z"
}
```

## Configuration

Environment variables read by the backend (`backend/app/config.py`, see `.env.example`):

| Variable | Default | Purpose |
|----------|---------|---------|
| `APPNAME` | SentryNode | Application name (used in logs/metadata) |
| `ENVIRONMENT` | development | Deployment environment label |
| `LOGLEVEL` | INFO | Logging verbosity |
| `JWTSECRET` | change-me | JWT secret for future auth features |
| `ABUSEIPDBAPIKEY` | change-me | AbuseIPDB API key for IP reputation lookups |
| `DISCORDWEBHOOKURL` | (unset) | Discord webhook for alert notifications (optional) |
| `REDISHOST` | localhost | Redis host for threat-intel response caching |
| `REDISPORT` | 6379 | Redis port |
| `REDISDB` | 0 | Redis logical database index |
| `REDISTTLSECONDS` | 3600 | Threat intel cache TTL, in seconds |
| `DEMOMODE` | false | Enables demo/showcase behavior (e.g. relaxed auth for the public demo deployment) |
| `CORSORIGINS` | "" (empty) | Comma-separated list of allowed CORS origins |

**docker-compose infra (not read by the backend):** `RABBITMQUSER`/`RABBITMQPASSWORD`, `INFLUXDBUSER`/`INFLUXDBPASSWORD`, `GRAFANAPASSWORD` configure the RabbitMQ, InfluxDB, and Grafana containers in `docker-compose.yml` for local full-stack development. They have no corresponding `Settings` field because the backend doesn't talk to those services yet (see Architecture above and Roadmap below).

## Testing

Run the test suite:

```bash
# Unit tests
docker compose exec backend pytest tests/unit/

# Integration tests (requires running services)
docker compose exec backend pytest tests/integration/

# With coverage
docker compose exec backend pytest --cov=app tests/
```

## Detection Rules

### SSH Brute Force
- **Trigger**: ≥ 5 failed SSH login attempts from same IP within 10 minutes
- **Severity**: HIGH
- **Action**: Alert generated, IP flagged

### SQL Injection
- **Trigger**: HTTP request path contains suspicious SQL patterns
- **Patterns**: `union select`, `drop table`, `insert into`, `delete from`, `../`, ` or 1=1`, `' or '1'='1`, `%27` (URL-encoded quote)
- **Severity**: CRITICAL
- **Action**: Alert generated immediately

Rules are configurable via `DetectionEngine` class initialization.

## Project Structure

```
sentrynode/
├── backend/                 # FastAPI application
│   ├── app/
│   │   ├── api/
│   │   │   └── routes/     # REST endpoints
│   │   │       ├── health.py
│   │   │       ├── logs.py
│   │   │       ├── alerts.py
│   │   │       └── threatintel.py
│   │   ├── services/       # Business logic
│   │   │   ├── detector.py      # Detection engine
│   │   │   └── threatintel.py   # Threat intel service
│   │   ├── config.py       # Configuration
│   │   └── main.py         # FastAPI app setup
│   ├── tests/              # Test suite
│   │   ├── unit/
│   │   └── integration/
│   └── Dockerfile
├── agent/                   # Log collection agents (future)
├── docker-compose.yml      # Full stack orchestration
├── .env.example            # Environment template
└── README.md
```

## Technology Stack

- **API Framework**: FastAPI 0.104.1
- **Async Runtime**: Uvicorn
- **Data Validation**: Pydantic 2.5
- **HTTP Client**: HTTPX
- **Caching**: Redis
- **Testing**: Pytest + pytest-asyncio
- **Logging**: python-json-logger
- **Infrastructure**: Docker Compose
  - Redis (caching — actively used)
  - RabbitMQ 3.12, Elasticsearch 8.11, InfluxDB 2.7, Grafana 10.2 — provisioned for local dev, not yet wired into the backend (see Roadmap)

## Development Roadmap (Phase 2+)

- [ ] Agent implementations (log collectors for SSH, nginx, Windows Event Log)
- [ ] Elasticsearch integration for centralized log storage
- [ ] InfluxDB metrics pipeline
- [ ] Grafana dashboard templates
- [ ] RabbitMQ event streaming
- [ ] Advanced correlation rules
- [ ] ML-based anomaly detection
- [ ] Authentication/authorization
- [ ] Multi-tenant support
- [ ] Alert notification channels (email, Slack, PagerDuty)

## Troubleshooting

**API not responding**
```bash
docker compose logs backend
docker compose ps
```

**Redis cache not working**
- Verify Redis container is running: `docker compose ps`
- Check backend logs for Redis connection errors

**AbuseIPDB lookups returning zeros**
- API key not configured: Set valid `ABUSEIPDBAPIKEY` in `.env`
- Rate limit hit: Responses are cached for 1 hour by default
- Network issue: Check backend container can reach api.abuseipdb.com

## Contributing

This is a portfolio/learning project. Contributions welcome! Please:
1. Fork and create a feature branch
2. Add tests for new features
3. Ensure all tests pass
4. Submit a pull request

## License

See LICENSE file for details.

---

**Built with**: FastAPI, RabbitMQ, Elasticsearch, InfluxDB, Grafana | **Status**: Active Development

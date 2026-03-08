# SentryNode

A lightweight, home-built Security Information and Event Management (SIEM) system for detecting, alerting, and analyzing security threats. SentryNode ingests logs from distributed agents, applies detection rules, correlates threat intelligence, and visualizes security metrics.

**Status**: Phase 1 - Local development with core detection and threat intel features

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

```
┌─────────────┐
│   Agents    │ (SSH logs, nginx logs, etc.)
└──────┬──────┘
       │ (HTTP POST /api/logs)
       ▼
┌─────────────────────────────────────┐
│    FastAPI Backend                  │
│  ┌──────────────────────────────┐   │
│  │  Detection Engine            │   │
│  │  - SSH Brute Force Rules     │   │
│  │  - SQL Injection Patterns    │   │
│  └──────────────────────────────┘   │
│  ┌──────────────────────────────┐   │
│  │  Threat Intel Service        │   │
│  │  - AbuseIPDB Integration     │   │
│  │  - Redis Caching             │   │
│  └──────────────────────────────┘   │
└─────────────┬───────────────────────┘
              │
    ┌─────────┴─────────┬──────────┬──────────┐
    ▼                   ▼          ▼          ▼
┌────────────┐  ┌────────────┐  ┌──────────┐  ┌────────┐
│Elasticsearch│ │ InfluxDB   │  │ RabbitMQ │  │ Redis  │
│  (Logs)    │  │ (Metrics)  │  │(Queuing) │  │(Cache) │
└────────────┘  └────────────┘  └──────────┘  └────────┘
                      │
                      ▼
                ┌────────────┐
                │  Grafana   │
                │(Dashboards)│
                └────────────┘
```

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
   Expected: `{"status":"ok"}`

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
Returns API status.

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

Environment variables (see `.env.example`):

| Variable | Default | Purpose |
|----------|---------|---------|
| `LOGLEVEL` | INFO | Logging verbosity |
| `RABBITMQUSER` | guest | RabbitMQ authentication |
| `RABBITMQPASSWORD` | guest | RabbitMQ authentication |
| `ABUSEIPDBAPIKEY` | change-me | AbuseIPDB API key for IP reputation |
| `INFLUXDBUSER` | admin | InfluxDB credentials |
| `INFLUXDBPASSWORD` | password123 | InfluxDB credentials |
| `GRAFANAPASSWORD` | admin | Grafana admin password |
| `DISCORDWEBHOOKURL` | (optional) | Discord webhook for alert notifications |
| `JWTSECRET` | change-me | JWT secret for future auth features |
| `REDISTTLSECONDS` | 3600 | Threat intel cache TTL |

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
  - RabbitMQ 3.12 (message queue)
  - Elasticsearch 8.11 (log indexing)
  - InfluxDB 2.7 (time-series metrics)
  - Grafana 10.2 (visualization)
  - Redis (caching)

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

**Elasticsearch connection error**
- Verify `ELASTICSEARCHHOST=elasticsearch` in backend container environment
- Check Elasticsearch is healthy: `curl http://localhost:9200`

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

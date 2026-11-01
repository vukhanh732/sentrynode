# SentryNode

A Python log collector and FastAPI detection API. SSH failures and suspicious HTTP requests become structured alerts that can be investigated through the API.

[Live API documentation](https://sentrynode-backend.onrender.com/docs) · [Alerts feed](https://sentrynode-backend.onrender.com/api/alerts) · [Portfolio case study](https://security-vu.netlify.app/sentrynode.html)

The public demo shows sample alerts and may take time to wake up. To send your own events, run the API locally with an agent token. The Render demo uses temporary storage.

## Working request path

```text
SSH / nginx log files
    → Python collector → bounded HTTP batches
    → FastAPI validation and rate limits
    → detection rules → SQLite alert history

IP reputation endpoint → AbuseIPDB → optional Redis cache
```

- The collector watches SSH and nginx logs and sends batches of up to 500 events.
- Rules detect SSH brute force and suspicious HTTP requests.
- A separate IP reputation endpoint uses AbuseIPDB and an optional Redis cache.

The Compose setup starts the API and Redis. RabbitMQ, Elasticsearch, InfluxDB and Grafana are not connected to the request path.

## Run the API locally

Python 3.10+:

```bash
git clone https://github.com/vukhanh732/sentrynode.git
cd sentrynode
python3 -m venv .venv
. .venv/bin/activate
pip install -r backend/requirements.txt
cd backend
export AGENT_TOKEN='replace-with-a-private-random-secret'
export ALERT_DB_PATH=data/alerts.sqlite3
DEMOMODE=true uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open <http://127.0.0.1:8000/docs>. Redis is optional. Set `ABUSEIPDBAPIKEY` for real reputation lookups; without it, the API labels results as unverified. See [`.env.example`](.env.example) for settings.

Try ingestion against your local instance:

```bash
curl -X POST http://127.0.0.1:8000/api/logs \
  -H 'Content-Type: application/json' \
  -H "X-Agent-Token: $AGENT_TOKEN" \
  -d '{"agentid":"local-demo","hostname":"web-01","events":[{"source":"nginx","httpmethod":"GET","httppath":"/../../etc/passwd","srcip":"192.0.2.10"}]}'
curl http://127.0.0.1:8000/api/alerts
```

For the local Docker demo, copy `.env.example` to `.env`, set a private `AGENT_TOKEN`, and run `docker compose up -d --build`. The named SQLite volume keeps alert history across container restarts; `docker compose down -v` removes it.

## Collector and delivery behavior

From the repository root, with the virtual environment active:

```bash
pip install -r agent/requirements.txt
cd agent
BACKEND_URL=http://127.0.0.1:8000 python -m collector.main
```

The default watch paths are `/var/log/auth.log` and `/var/log/nginx/access.log`; configure them in [`AgentConfig`](agent/collector/config.py) for your host. The process needs read access to those files.

The shipper retries the same payload after temporary failures:

| Condition | Delivery behavior |
| --- | --- |
| Transport error, HTTP 408 / 429 / 5xx | Initial attempt plus at most five retries |
| Retry delay | 1, 2, 4, 8, 16 seconds; numeric `Retry-After` is capped at 30 seconds |
| Other HTTP errors | Fail immediately |
| More than 500 events | Send sequential chunks, stopping if a chunk fails |
| Task cancellation | Propagate cancellation |

There is no disk spool. Batches can be lost after retries or duplicated after an ambiguous timeout. The API rejects missing or invalid agent tokens.

## Verify

From the repository root with backend dependencies installed:

```bash
(cd backend && python -m pytest tests/unit -q)
(cd agent && python -m pytest tests -q)
```

Tests cover detection, authentication, alert persistence, reputation failures, collector parsing and delivery retries. HTTP delivery tests use mocked transports. Integration tests under `backend/tests/integration` require running services.

## Scope and next work

Alert history is stored in SQLite. Detection windows reset on restart. This project has not been tested at production scale.

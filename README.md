# SentryNode

A Python log collector and FastAPI detection API. SSH failures and suspicious HTTP requests become structured alerts that can be investigated through the API.

[Live API documentation](https://sentrynode-backend.onrender.com/docs) · [Alerts feed](https://sentrynode-backend.onrender.com/api/alerts) · [Portfolio case study](https://security-vu.netlify.app/sentrynode.html)

The public Render demo uses sample alerts and in-memory state. It may take time to wake after inactivity. It is a learning project, not a production SIEM.

## Working request path

```text
SSH / nginx log files
    → Python collector → bounded HTTP batches
    → FastAPI validation and rate limits
    → detection rules → in-memory alert feed

IP reputation endpoint → AbuseIPDB → optional Redis cache
```

- Collector parses SSH and nginx log lines and watches configured files.
- Detection covers SSH brute force, SQL injection, path traversal, HTTP authentication failures, method scanning and suspicious paths.
- Ingestion accepts at most 500 events per request, with a 20-request/minute client limit. IP reputation lookups are limited to 30/minute.
- The separate reputation endpoint caches AbuseIPDB responses and handles unavailable upstream services. A missing API key returns an explicitly labelled default, not a verified clean reputation.

RabbitMQ, Elasticsearch, InfluxDB and Grafana are provisioned in Compose for experimentation. They are **not connected to the implemented ingestion path**.

## Run the API locally

Python 3.10+:

```bash
git clone https://github.com/vukhanh732/sentrynode.git
cd sentrynode
python3 -m venv .venv
. .venv/bin/activate
pip install -r backend/requirements.txt
cd backend
DEMOMODE=true uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open <http://127.0.0.1:8000/docs>. Redis is optional; `/health` reports its availability. Set `ABUSEIPDBAPIKEY` to enable real reputation lookups. The complete environment template is [`.env.example`](.env.example).

Try ingestion against your local instance:

```bash
curl -X POST http://127.0.0.1:8000/api/logs \
  -H 'Content-Type: application/json' \
  -d '{"agentid":"local-demo","hostname":"web-01","events":[{"source":"nginx","httpmethod":"GET","httppath":"/../../etc/passwd","srcip":"192.0.2.10"}]}'
curl http://127.0.0.1:8000/api/alerts
```

For the full experimental stack, copy `.env.example` to `.env` and run `docker compose up -d --build`. Review local container credentials before exposing any services.

## Collector and delivery behavior

From the repository root, with the virtual environment active:

```bash
pip install -r agent/requirements.txt
cd agent
BACKEND_URL=http://127.0.0.1:8000 python -m collector.main
```

The default watch paths are `/var/log/auth.log` and `/var/log/nginx/access.log`; configure them in [`AgentConfig`](agent/collector/config.py) for your host. The process needs read access to those files.

The shipper now retries the **same payload**, rather than waiting and discarding it after the first failed request:

| Condition | Delivery behavior |
| --- | --- |
| Transport error, HTTP 408 / 429 / 5xx | Initial attempt plus at most five retries |
| Retry delay | 1, 2, 4, 8, 16 seconds; numeric `Retry-After` is capped at 30 seconds |
| Other HTTP errors | Fail immediately |
| More than 500 events | Send sequential chunks, stopping if a chunk fails |
| Task cancellation | Propagate cancellation |

There is no durable queue or disk spool. Exhausted batches can be lost, and an ambiguous timeout can lead to duplicates when retried. Earlier chunks may already have been accepted when a later chunk fails. The `X-Agent-Token` header is sent by the collector, but the current API does not enforce agent authentication.

## Verify

From the repository root with backend dependencies installed:

```bash
(cd backend && python -m pytest tests/unit -q)
(cd agent && python -m pytest tests -q)
```

Tests cover detection, API validation/rate limits, reputation/cache failure handling, parsing/file watching, retry exhaustion, permanent errors, payload chunking and cancellation. HTTP delivery tests use mocked transports; they do not send events to the public demo. Integration tests under `backend/tests/integration` additionally require running services.

## Scope and next work

Alerts and detection windows live in process memory and reset on restart. Durable ingestion, authenticated agents and persistent alert storage remain future work. Current evidence demonstrates the API and collector behavior, not production scale or detection effectiveness against all attacks.

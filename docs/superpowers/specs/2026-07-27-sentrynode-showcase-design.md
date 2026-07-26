# SentryNode Public Showcase — Design

**Date**: 2026-07-27
**Status**: Approved

## Goal

Make SentryNode safe and impressive to show recruiters: a polished, honest
codebase, a live hosted demo of the backend, and a static showcase page
linking to both — without adding new features or a desktop installer.

## Context

SentryNode is a home-built SIEM: a FastAPI backend with an in-memory
detection engine (SSH brute force, SQL injection, path traversal, HTTP
method scanning, HTTP auth brute force, suspicious path access) and an
AbuseIPDB-backed threat-intel lookup cached in Redis. `docker-compose.yml`
also provisions RabbitMQ, InfluxDB, Elasticsearch, and Grafana, and the
README's architecture diagram presents them as part of the system.

Investigation of the actual code found that RabbitMQ and InfluxDB are never
referenced in `backend/app/`, and `ElasticsearchService` exists as a fully
built class (indexing, search, timeline aggregation) but is never imported
or called anywhere — dead code. The only real runtime dependency is Redis,
used by `ThreatIntelService` for caching AbuseIPDB responses. That service
also has a real bug: no error handling around its Redis calls, so an
unreachable Redis raises an unhandled exception instead of degrading
gracefully, and it opens a new Redis connection per request instead of
reusing one.

Because the code's real dependency footprint is much smaller than the
docs suggest, the deployable "demo" doesn't need to be a cut-down version
of the architecture — it just needs the Redis dependency made optional and
robust, after which the existing backend Dockerfile can run standalone
with zero external services.

Netlify hosts static sites/serverless functions only — it cannot run the
Docker Compose stack, so "deploy to Netlify" is being split into: a live
backend demo hosted where containers can run (Render), and a static
showcase/portfolio page on Netlify that links to it.

Decisions already made with the user:
- Primary goal: live hosted demo + a Netlify showcase page (not just a
  static page, and not the full multi-service stack running publicly).
- Demo scope: a slim backend demo (SQLite/in-memory + optional Redis),
  not the full docker-compose stack on a paid VPS.
- Review depth: polish for public release (bug fixes, security hardening
  for public exposure, code quality, doc accuracy) — no new features.
- Hosting: Render free Web Service tier (accepted trade-off: cold start
  of ~30-60s after ~15 min idle).
- No Windows installer/.exe — rejected as a mismatch for a multi-service
  backend project; documented reasoning already shared with the user.

## Scope

### In scope

1. **Backend polish** (bug fixes and hardening only, no new features):
   - Fix `ThreatIntelService`: wrap Redis calls in try/except so a
     missing/unreachable Redis degrades to "no cache" instead of raising;
     reuse a single Redis client instance; switch to `redis.asyncio` so
     Redis I/O doesn't block the event loop. There's no separate
     enable/disable flag — the service always attempts to use Redis and
     silently runs cache-free whenever it's unreachable, which is what
     allows the deployed demo to run as a single container with no Redis
     provisioned at all, without needing to remember to configure
     anything.
   - Cap `POST /api/logs` batch size (e.g. max 500 events per request) to
     bound memory use from a single request.
   - Add lightweight per-IP rate limiting (`slowapi`) on `POST /api/logs`
     and `GET /api/threat-intel/{ip}` — primarily to protect the
     AbuseIPDB free-tier quota and prevent abuse of a publicly reachable
     write endpoint.
   - Validate the `ip` path parameter in the threat-intel endpoint is a
     real IP address (`ipaddress.ip_address`) before using it.
   - Add CORS restricted to the Netlify showcase domain, so the showcase
     page can call the live API from browser JS if desired.
   - Fix `GET /health` to reflect actual Redis status when Redis is
     configured, instead of an unconditional `{"status": "ok"}`.
   - Delete the unused `ElasticsearchService` (dead code). Correct the
     README's architecture section to clearly separate "implemented and
     running today" (detection engine, threat intel + Redis cache) from
     "provisioned in docker-compose for local full-stack dev, not yet
     wired into the request path" (RabbitMQ, InfluxDB, Elasticsearch,
     Grafana). Frame this as an accurate roadmap, not a deficiency.
   - Add tests for the new error-handling paths: Redis unavailable,
     invalid IP input, oversized log batch, rate-limit triggered.

2. **Demo data seeding**: on startup, when a `DEMO_MODE` env flag is set,
   seed a handful of realistic sample alerts (SSH brute force, SQL
   injection, path traversal) into the in-memory engine so
   `GET /api/alerts` isn't empty on first load. Live ingestion continues
   to work on top of the seeded data.

3. **Deployment**: deploy `backend/Dockerfile` as a Render free-tier
   Docker Web Service, connected to the GitHub repo for auto-deploy on
   push to `main`. No other managed services required.

4. **Showcase page**: a single static HTML/CSS page (no build step)
   deployed to Netlify, covering what SentryNode is, an accurate
   architecture section (implemented vs. roadmap, framed positively),
   screenshots/GIFs of the Swagger docs and a live-generated alert, a
   "try it live" link to the Render-hosted `/docs`, and a link to the
   GitHub repo. Includes a note that the first request after idle may
   take ~30-60s (Render free-tier cold start).

### Out of scope

- No Windows installer/.exe.
- No new detection rules or product features.
- No public hosting of the full RabbitMQ/InfluxDB/Elasticsearch/Grafana
  stack.
- No authentication system (JWT secret exists in config but is unused
  today; rate limiting + payload caps are considered sufficient for a
  public demo of this size, given there's nothing sensitive/persistent at
  stake).

## Testing

- Existing unit test suite (42 passing tests as of this review) continues
  to pass.
- New unit tests cover: Redis-down graceful degradation in
  `ThreatIntelService`, invalid IP rejection, oversized batch rejection,
  rate-limit behavior.
- Manual verification: hit the deployed Render URL's `/health` and
  `/docs`, POST a sample SSH brute-force log batch and confirm an alert
  appears via `GET /api/alerts`, confirm the showcase page loads on
  Netlify and its "try it live" link works end to end.

## Risks / trade-offs accepted

- Render free tier cold starts (~30-60s after idle) — mitigated by
  documenting it on the showcase page.
- In-memory alert/engine state resets on every backend restart/redeploy
  (no persistent DB in the slim demo) — acceptable for a demo; seeded
  demo data means it's never empty.
- No auth on the demo's write endpoint — mitigated by rate limiting and
  batch size caps; acceptable because the demo holds no sensitive or
  persistent data.

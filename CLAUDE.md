# Mini SIEM Tool — Project Instructions

Global conventions (effort routing, permission gates, explain-as-you-go, token discipline) live in
~/.claude/CLAUDE.md and apply here without repetition. This file covers only what's specific to
Mini SIEM. Full spec: mini-siem-master-guide.md.

## Stack
FastAPI + PostgreSQL + OpenSearch + Redis + Celery + Next.js (App Router) + Tailwind +
Framer Motion + GSAP + Recharts/Tremor. Docker Compose for all services.

## Non-negotiable decisions (do not re-litigate)
- OpenSearch, not Elasticsearch — licensing (SSPL vs Apache 2.0).
- Detection rules are YAML/Sigma-style, evaluated via Celery periodic sweeps — near-real-time,
  not a true streaming engine. Never describe this as "real-time streaming" in code, docs, or UI copy.
- JWT RS256, refresh-token rotation with reuse detection (a replayed used token kills the whole
  session family).
- Three roles: admin, analyst, viewer. No more, no fewer, without an explicit decision.
- Dark theme only. No light mode.
- Argon2 or bcrypt for password hashing.

## Model routing for this project
Default is opusplan (Opus plans, Sonnet implements). These areas get Opus for *implementation
too*, not just planning — flag it explicitly before starting work here, even mid-task:
- Detection rule engine (`backend/app/services/detection/`)
- Auth / JWT / RBAC logic (`backend/app/core/security.py`, `backend/app/api/auth/`, permission
  dependencies)
- Celery/Redis/WebSocket wiring (`backend/app/workers/`, `backend/app/websockets/`, broker/queue config)

Everything else — CRUD endpoints, React components, tests, Docker config, straightforward bug
fixes — runs on Sonnet once the plan is agreed.

## Testing
- pytest for backend, especially the detection rule engine and auth flows.
- Every new detection rule needs a corresponding test fixture (sample log lines that should/
  shouldn't trigger it).
- No "should work" claims on detection or auth logic without a passing test.

## Subagents (.claude/agents/)
- `planner.md` — breaks down HARD/MAX tasks, no code writing
- `reviewer.md` — reads diffs only, checks security/logic, doesn't fix
- `security-auditor.md` — reviews auth, input handling, dependency risk (used heavily in Phase 10)

Invoke explicitly; don't auto-spawn on every task.

## Phase plan (checkpoint by checkpoint — confirm before moving to the next)
1. Scaffolding — folders, Docker skeleton, CLAUDE.md, empty FastAPI + Next.js talking to each other
2. Auth + RBAC
3. Log ingestion pipeline
4. Detection engine
5. IOC enrichment
6. Alerts + Incidents
7. WebSocket live feed
8. Dashboard + charts
9. Command palette, timeline scrubber, animation polish
10. Self-attack testing (Burp/PortSwigger loop) — document every finding like a real detection gap
11. Deployment (Oracle Cloud VM, Cloudflare, GitHub Actions)
12. Resume/README polish

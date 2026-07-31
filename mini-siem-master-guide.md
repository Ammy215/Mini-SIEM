# Mini SIEM Master Guide
### Enterprise-Grade Security Information & Event Management Platform
*A full specification for Claude Code, built the same way the Metadata & File Intelligence Analyzer was scoped.*

---

## Part 0 — How This Guide Works

This is a companion document to your `project_context.md` pattern. Once this project starts, paste **Part 0's role block** into your first message to me in a fresh chat, and I become your Mini SIEM advisor the same way I was for the Metadata Analyzer — you paste Claude Code screenshots/checkpoints, I tell you what to click and what to paste back.

### Role block (paste this at the top of your first Mini SIEM chat with me)

```
I'm building the Mini SIEM Tool described in mini-siem-master-guide.md (attached).
Act as my technical advisor for this project the way you did for my Metadata &
File Intelligence Analyzer — Claude Code (in VS Code) writes the actual code; you
explain what it's doing in plain language, help me pick between Plan Mode options,
write the exact copy-paste replies I send back to Claude Code, and flag anything
risky or inconsistent with the decisions in this guide. I'm not a professional
developer — tell me exactly what to type/click/select, step by step.
```

### Kickoff prompt (paste this into Claude Code / VS Code to start Phase 1)

```
I'm starting a new project called Mini SIEM Tool. Read the attached
mini-siem-master-guide.md fully before doing anything else — it contains the
complete architecture, tech stack, folder structure, and phase plan.

Also check whether I have a global CLAUDE.md at ~/.claude/CLAUDE.md. If it
exists, read it — it holds conventions that apply across all my projects
(working style, git workflow, testing philosophy), and this project should
follow it, not repeat or contradict it.

Do NOT write any code yet. Instead:
1. Confirm you've understood the architecture by summarizing it back to me in
   your own words (5-6 bullet points max).
2. Propose the exact folder structure you'll scaffold, matching Part 1 of the
   guide.
3. Draft a project-level CLAUDE.md for this repo — informed by my global
   CLAUDE.md (if one exists) plus the non-negotiable decisions and phase plan
   in the master guide's Part 4. Show it to me before writing it to disk.
4. List any clarifying questions before we start Phase 1 (project scaffolding
   + Docker skeleton + the CLAUDE.md we just agreed on).

Use Plan Mode. Do not proceed past this check-in without my explicit approval.
```

---

## Part 1 — Vision & Architecture

### Vision
A self-hosted, single-tenant SIEM that ingests logs from real sources (your own machine, a test VM, or sample datasets), parses and normalizes them, runs rule-based + IOC-based detections, and surfaces alerts on a live enterprise-style dashboard — then gets attacked by you (via Burp/PortSwigger techniques) so you can watch it detect its own compromise attempts in real time.

### Core requirements
- Ingest logs from at least 3 source types: auth logs (SSH/Linux), web server access logs (nginx/Apache), and application logs (your own FastAPI backend's audit log)
- Normalize all sources into one common event schema (ECS-inspired, not full ECS)
- Rule engine evaluates events against detection rules in near-real-time
- IOC enrichment: match event fields (IPs, hashes, domains) against threat intel feeds
- Alerts persist with severity, MITRE ATT&CK technique tags, and a status workflow (new → investigating → resolved)
- Incident timeline view: reconstruct a sequence of related events into one narrative
- Dashboards: live event feed, alert volume over time, top offending IPs, detection rule hit-rates
- The app's own auth endpoints are the first monitored data source (you attack yourself, the SIEM watches)

### Complete tech stack

| Layer | Choice | Why |
|---|---|---|
| Backend | FastAPI (Python) | Matches your existing stack, async-native |
| Search/storage engine | OpenSearch (Elasticsearch-compatible, Apache 2.0 licensed, free forever) | Elasticsearch itself has restrictive licensing on newer versions; OpenSearch is the drop-in open fork — same query DSL, same client libraries, zero licensing risk |
| Relational DB | PostgreSQL | Users, rules, alert metadata, RBAC — anything relational |
| Cache/broker | Redis | Rate limiting, Celery broker, WebSocket pub/sub |
| Background jobs | Celery | Log ingestion pipeline, enrichment jobs, scheduled rule sweeps |
| Real-time | WebSockets (FastAPI native) | Live event feed, live alert push to dashboard |
| Frontend framework | Next.js (React) | File-based routing, easy SSR for a polished landing/README demo page |
| Styling | Tailwind CSS | Matches your existing dark cyber theme approach |
| Animation | Framer Motion (alert transitions, panel entrances) + GSAP (timeline scrubber, command palette) | Framer Motion for React-native component animation; GSAP for the one or two complex custom-timeline interactions where Framer's declarative model gets awkward |
| Charts | Recharts or Tremor (dashboard-focused chart library) | Enterprise dashboard look with minimal custom SVG work |
| Auth | JWT (RS256, matches your ThreatHunter decisions) | Consistency with your existing security decisions |
| Containerization | Docker Compose | Same pattern as Metadata Analyzer: backend, frontend, celery_worker, redis, postgres, opensearch |

### Why OpenSearch instead of Elasticsearch
Elastic changed licensing in 2021 (SSPL/Elastic License, not fully open source past v7.10). OpenSearch is the AWS-led open-source fork, stayed Apache 2.0, and is what most free-tier-friendly and enterprise-neutral SIEMs (including parts of Wazuh) actually build on. Same API surface — anything you learn transfers directly to real Elasticsearch/Elastic Stack knowledge, which is what's on job descriptions.

### Folder structure

```
mini-siem/
├── backend/
│   ├── app/
│   │   ├── api/                  # FastAPI routers (auth, alerts, rules, logs, dashboard)
│   │   ├── core/                 # config, security, dependencies
│   │   ├── models/                # SQLAlchemy models (Postgres side)
│   │   ├── schemas/               # Pydantic schemas
│   │   ├── services/
│   │   │   ├── ingestion/         # log collectors + parsers per source type
│   │   │   ├── detection/         # rule engine
│   │   │   ├── enrichment/        # IOC/threat intel lookups
│   │   │   └── opensearch/        # OpenSearch client + index management
│   │   ├── workers/                # Celery tasks
│   │   ├── websockets/             # connection manager, event broadcaster
│   │   └── main.py
│   ├── rules/                      # YAML/Sigma-style detection rule definitions
│   ├── tests/
│   ├── alembic/
│   └── Dockerfile
├── frontend/
│   ├── app/                        # Next.js app router
│   │   ├── dashboard/
│   │   ├── alerts/
│   │   ├── timeline/
│   │   ├── rules/
│   │   └── login/
│   ├── components/
│   │   ├── charts/
│   │   ├── live-feed/
│   │   ├── command-palette/
│   │   └── terminal-ui/
│   ├── lib/
│   └── Dockerfile
├── ingestion-samples/               # sample log files for dev (auth.log, nginx access.log)
├── docker-compose.yml
├── CLAUDE.md
└── mini-siem-master-guide.md
```

### System design (high level)

```
[Log Sources] → [Collectors] → [Parser/Normalizer] → [Celery Queue]
                                                            │
                                                            ▼
                                              [Detection Rule Engine]
                                                            │
                                          ┌─────────────────┴─────────────────┐
                                          ▼                                   ▼
                                 [OpenSearch: raw events]         [Postgres: alerts, incidents]
                                          │                                   │
                                          └────────────┬──────────────────────┘
                                                        ▼
                                         [FastAPI API + WebSocket broadcaster]
                                                        │
                                                        ▼
                                            [Next.js Dashboard — live feed,
                                             charts, timeline, alert triage]
```

### UI inspiration
Splunk Enterprise Security, Microsoft Sentinel, Elastic Security, and CrowdStrike Falcon dashboards — dark theme, monospace for log/event data, glassmorphism panels for cards, a command palette (Cmd+K) for power-user navigation, and a terminal-style live event feed that scrolls like `tail -f`.

---

## Part 2 — Backend

### Authentication
- JWT access + refresh tokens, RS256 (asymmetric — same reasoning as ThreatHunter: lets you rotate/verify without sharing the signing key across services)
- Argon2 or bcrypt password hashing
- Refresh token rotation with reuse detection (if a used-up refresh token is replayed, kill the whole session family — this is itself a detection signal you'll feed into the SIEM later)

### RBAC
Three roles to start:
- **Admin** — full access, manage rules, manage users, see all data
- **Analyst** — view alerts/timelines, triage (change alert status), cannot manage rules or users
- **Viewer** — read-only dashboard access (useful for a "demo mode" you can show recruiters without giving them triage power)

### Core APIs
- `/api/v1/auth/*` — login, refresh, logout
- `/api/v1/events/*` — query normalized events (proxies to OpenSearch)
- `/api/v1/alerts/*` — list/filter/update alert status
- `/api/v1/rules/*` — CRUD for detection rules (admin only)
- `/api/v1/incidents/*` — grouped alert timelines
- `/api/v1/dashboard/*` — aggregate stats for charts
- `/api/v1/ws/live` — WebSocket endpoint for live event/alert push

### Detection rule engine
Start with a YAML-based rule format loosely modeled on **Sigma** (the open, vendor-neutral detection rule standard used by real SOC teams — this is a strong resume line on its own):

```yaml
title: Multiple Failed Logins Followed By Success
id: brute-force-success
severity: high
mitre_attack: [T1110]  # Brute Force
detection:
  source: auth
  condition: >
    5+ failed_login events from same source_ip within 2 minutes,
    followed by 1 successful_login from same source_ip
tags: [authentication, brute-force]
```

The engine evaluates rules against the event stream via Celery periodic tasks (near-real-time, not literally streaming — be upfront about this distinction in interviews, it's the honest and correct answer).

### IOC enrichment
- Local IOC list you maintain (CSV/JSON of known-bad IPs, hashes) — no external dependency required
- Optional: free-tier threat intel lookups (AbuseIPDB free tier, 1000 requests/day) for IP reputation — cache results in Redis so you don't burn the quota
- Every enriched field gets attached to the event before it's indexed, so alerts show "this IP has 40 abuse reports" inline

### Caching
Redis for: rate limiting (same failure-counting pattern as your Metadata Analyzer), IOC lookup caching, WebSocket pub/sub fan-out across multiple backend instances (future-proofing, even at 1 instance).

### Background workers
Celery queues, split by purpose so one slow queue can't starve another:
- `ingestion` — pulls/tails raw logs, normalizes, writes to OpenSearch
- `detection` — runs rule evaluation sweeps
- `enrichment` — IOC lookups

---

## Part 3 — Frontend

### Stack
Next.js (App Router) + Tailwind + Framer Motion + GSAP + Recharts/Tremor.

### Key screens
1. **Login** — dark cyber theme, matches Metadata Analyzer's existing design language
2. **Dashboard** — alert volume chart, severity breakdown, top source IPs, live event feed panel
3. **Live Event Feed** — terminal-style, auto-scrolling, WebSocket-driven, pausable
4. **Alerts** — filterable table, severity badges, click into an alert for detail + linked raw events
5. **Incident Timeline** — horizontal scrubber (GSAP-driven) showing a reconstructed attack sequence
6. **Rules** — list/create/edit detection rules (admin), with a "test this rule against sample data" button
7. **Command Palette** (Cmd+K) — jump to any screen, search alerts, trigger actions — this is the single highest "wow factor per hour of dev time" feature you can add

### Interaction details worth the extra polish
- New alerts animate into the live feed with a Framer Motion slide-in + a brief glow pulse scaled to severity color
- Keyboard shortcuts: `g d` (go dashboard), `g a` (go alerts), `/` (focus search), `Cmd+K` (command palette) — label these in a small shortcuts modal (`?`)
- Dark mode is the only mode — don't build a light theme, it's wasted effort for a security-tool aesthetic

---

## Part 4 — Claude Code Engineering

### Global CLAUDE.md vs project CLAUDE.md
Claude Code supports two levels of instructions:
- **Global** — `~/.claude/CLAUDE.md`. Applies to every project on your machine. This is where cross-project conventions belong: your working style (Plan Mode for big changes, checkpoint-sized diffs, no "should work" claims without a passing test, explain-before-implementing since you're not a professional developer), your git workflow habits, your general testing philosophy. If you don't have this file yet, this is a good project to start it on — anything you'd otherwise repeat in every project's CLAUDE.md belongs here instead.
- **Project** — `<repo>/CLAUDE.md`. Applies only to Mini SIEM. This is where the project-specific, non-negotiable decisions live (OpenSearch not Elasticsearch, three roles, dark theme only, Celery-sweep detection not true streaming) — the stuff below.

The two are meant to compose, not duplicate. If a rule belongs in both, put it in global only and let the project one stay lean.

### Have Claude Code write its own project CLAUDE.md
Don't hand Claude Code a finished CLAUDE.md — hand it the decisions (below) and your global CLAUDE.md, and have it draft the project-level file itself as the first checkpoint of Phase 1 (this is already built into the kickoff prompt in Part 0). Claude Code writes better project instructions when it has actually seen the scaffolded repo structure it's describing, and drafting it itself forces an early comprehension check — if its draft misstates a decision, you catch a misunderstanding before any code gets written instead of after.

The block below is the **source material** to hand it, not the final file:

```markdown
# Mini SIEM Tool — Project Instructions

## Stack
FastAPI + PostgreSQL + OpenSearch + Redis + Celery + Next.js + Tailwind.
Docker Compose for all services. See mini-siem-master-guide.md for full spec.

## Non-negotiable decisions (do not re-litigate)
- OpenSearch, not Elasticsearch (licensing).
- Detection rules are YAML/Sigma-style, evaluated via Celery periodic sweeps —
  this is near-real-time, not a true streaming engine. Never claim "real-time
  streaming" in comments, docs, or UI copy.
- JWT RS256, refresh rotation with reuse detection.
- Three roles: admin, analyst, viewer.
- Dark theme only. No light mode.

## Working style
- Plan Mode for anything touching more than 2 files or any architecture decision.
- Break large changes into reviewable checkpoints, not one giant diff.
- After any change to detection or auth logic, write/run an actual test —
  no "should work" claims without a passing test to back it up.
- I am not a professional developer. Explain plans in plain language before
  implementing.

## Testing
- pytest for backend, especially detection rule engine and auth flows
- Every new detection rule needs a corresponding test fixture (sample log
  lines that should/shouldn't trigger it)
```

Paste that block into Claude Code as reference, not as a file to save — ask it to rewrite it in its own words once the real folder structure exists, and to fold in anything from your global CLAUDE.md rather than repeating it.

### Recommended MCP servers for this project
- **GitHub MCP** (you already have this set up) — commits, PRs, issue tracking
- **Filesystem MCP** — if you want Claude Code to reason over the sample log files without pasting them manually
- **Postgres MCP** (optional, later) — lets Claude Code inspect your actual schema state directly instead of guessing from migration files

### Hooks worth setting up
- A pre-commit hook (via Claude Code's hook system) that runs `pytest` and `eslint` before allowing a commit message to be generated — catches regressions before they're even proposed to you
- A post-tool-use hook that logs every file Claude Code modifies to a `CHANGELOG_CLAUDE.md` — genuinely useful for your own memory of what happened across a multi-week project, and doubles as a "how I worked with AI" artifact for interviews

### Suggested phase plan (for Claude Code, checkpoint by checkpoint)
1. Scaffolding — folder structure, Docker skeleton, CLAUDE.md, empty FastAPI + Next.js apps talking to each other
2. Auth + RBAC — JWT, roles, protected routes both sides
3. Log ingestion pipeline — collectors, normalizer, OpenSearch indexing, sample data
4. Detection engine — rule format, evaluator, first 3-5 rules working end-to-end
5. IOC enrichment — local IOC list, optional AbuseIPDB integration
6. Alerts + Incidents — API, DB models, status workflow
7. WebSocket live feed — backend broadcaster, frontend consumer
8. Dashboard + charts
9. Command palette, timeline scrubber, keyboard shortcuts, animation polish
10. PortSwigger-style self-attack testing (Part 5) — find real bugs, fix them, document them like Phases 1-9 of the Metadata Analyzer
11. Deployment (Part 6)
12. Resume/README polish (Part 7)

---

## Part 5 — Security Testing (Attack Your Own SIEM)

This is the differentiator most portfolio projects skip. Document every finding the same way you documented Metadata Analyzer bugs — that log is itself a resume asset.

### What to test, and with what
| Target | Tool/technique | What you're checking |
|---|---|---|
| Login endpoint | Burp Intruder | Brute-force resistance, does the SIEM's own brute-force rule fire? |
| JWT | Burp + jwt_tool | alg confusion, weak secret, expiry handling, refresh reuse detection |
| REST APIs | Burp Repeater | IDOR — can analyst A view analyst B's alerts by changing an ID? |
| Rate limiting | Custom script or Burp Turbo Intruder | Does it actually throttle, and does throttling itself generate a SIEM event? |
| Vulnerable dev routes (intentionally added, non-prod only) | Burp Scanner | XSS, SQLi — confirm the app is vulnerable, confirm the SIEM detects the attempt, then patch |
| CSRF | Burp CSRF PoC generator | State-changing endpoints without CSRF protection |

### The loop that makes this project stand out
1. Attack a specific endpoint
2. Confirm the SIEM logged and alerted on the attempt (or didn't — that's a finding too)
3. If it didn't detect it, write a new detection rule
4. Re-run the attack, confirm detection now fires
5. Document: what you attacked, what happened, what rule you wrote, before/after screenshot of the alert firing

That loop — attack, observe gap, write detection, verify — is literally what a detection engineer does in a real SOC. Say exactly that in your resume bullet and interview answers.

### OWASP Top 10 mapping (use as your checklist)
A01 Broken Access Control (RBAC/IDOR tests) · A02 Cryptographic Failures (JWT alg, password hashing) · A03 Injection (intentional dev-only SQLi route) · A05 Security Misconfiguration (headers, CORS, Docker) · A07 Auth Failures (brute force, session fixation) · A08 Data Integrity Failures (JWT tampering).

### Security headers checklist
CSP, X-Content-Type-Options, X-Frame-Options, Strict-Transport-Security (once behind TLS termination), Referrer-Policy — same reasoning as your ThreatHunter nginx work: termination happens externally, but the app still sends the right headers.

---

## Part 6 — Deployment (Zero Cost)

### The constraint that shapes this: OpenSearch is memory-hungry
Free-tier PaaS platforms (Render, Railway, Fly.io) give you small containers with limited RAM, and most don't let you run a 5-service stack (backend, frontend, worker, redis, postgres, *and* opensearch) for free at once.

### Recommended path: Oracle Cloud Always Free tier
Oracle's Always Free tier includes an ARM-based VM (up to 4 OCPUs / 24GB RAM, genuinely free forever, not a trial) — enough to comfortably self-host your entire Docker Compose stack including OpenSearch, the way you'd run it in a real small-company environment. This is different from Render/Railway/Fly's "free until it isn't" tiers.

**Deployment shape:**
- Oracle Cloud VM: runs the full `docker-compose.yml` stack (backend, frontend, celery_worker, redis, postgres, opensearch)
- Cloudflare (free): DNS + TLS termination in front of the VM (matches your existing "external TLS termination" decision from the Metadata Analyzer) + basic DDoS/rate protection
- GitHub Actions (free tier): CI — run tests, build images, optionally SSH-deploy to the VM on merge to `main`

**Fallback path** (if you'd rather not manage a VM): split the stack —
- Frontend → Vercel free tier
- Backend → Render free web service
- Postgres → Neon or Supabase free tier
- Redis → Upstash free tier
- OpenSearch → this is the hard part on this path; either run a small self-hosted OpenSearch on a free Oracle VM *just* for that one service, or substitute PostgreSQL full-text search + a materialized view for the portfolio-demo version and be upfront in your README that production would use OpenSearch/Elastic properly

Given you already have Docker Compose experience from the Metadata Analyzer, the **Oracle Cloud VM path is the better learning outcome** — it's the closest to how a real small SOC actually runs infrastructure, and it avoids awkward architecture compromises just to fit a free tier.

### CI/CD (GitHub Actions, free)
- On PR: lint + test (pytest, ESLint)
- On merge to `main`: build Docker images, push to GHCR (GitHub Container Registry, free for public repos), SSH into the Oracle VM and `docker compose pull && docker compose up -d`

### Monitoring (free)
- Docker Compose `healthcheck` blocks on every service (you already have this pattern)
- Uptime Robot (free tier) pinging your public URL, alerts you by email/Discord if it goes down — a nice full-circle touch: a SIEM project that's itself monitored

---

## Part 7 — Resume & Interview Prep

### Resume bullet points (draft — tune numbers once real)
- Built a full-stack SIEM platform (FastAPI, OpenSearch, PostgreSQL, Redis/Celery, Next.js) implementing log normalization, Sigma-style detection rules, IOC enrichment, and MITRE ATT&CK-mapped alerting
- Designed and executed a red-team/blue-team testing loop against the platform's own auth and API layer using Burp Suite (JWT tampering, IDOR, brute-force, CSRF), closing every detection gap found with a new rule and verifying re-detection
- Implemented RBAC with three permission tiers, JWT (RS256) with refresh-token rotation and reuse detection, and rate limiting across all public endpoints
- Self-hosted the full stack (6 containerized services) on Oracle Cloud with GitHub Actions CI/CD and Cloudflare TLS termination — zero infrastructure cost

### GitHub README structure
1. 30-second GIF/screen-recording of the live event feed + an alert firing in real time (this single asset does more work than any paragraph of text)
2. One-paragraph "what and why"
3. Architecture diagram (reuse the one from Part 1)
4. The attack-and-detect loop as a worked example (screenshot: attack in Burp → alert fires in dashboard)
5. Tech stack table
6. Local setup instructions (`docker compose up`)
7. "What I'd do with more time" section — honest, shows maturity

### Likely interview questions this project prepares you for
- "Walk me through what happens from a raw log line to an alert on the dashboard." (tests real understanding of your own pipeline)
- "Why OpenSearch instead of Elasticsearch, or a plain database?" (licensing + search-at-scale reasoning)
- "How would this handle 10,000 events per second? What breaks first?" (be honest: Celery periodic sweeps, not true streaming, is your current bottleneck — say what you'd change: Kafka/streaming consumer)
- "How did you find and fix a real detection gap?" (this is why the attack-loop documentation in Part 5 matters — have a specific story ready)
- "What's the difference between a SIEM and a SOAR?" (know this cold — SIEM detects/aggregates, SOAR automates response; you built the former)

### Future roadmap (good "what's next" answer, don't build all of this now)
- Real streaming ingestion (Kafka or Redpanda) instead of Celery polling
- SOAR-style automated response (auto-block an IP after N failed logins)
- Multi-tenant support
- Sigma rule import from the public Sigma ruleset repo, not just hand-written rules
- ML-based anomaly detection layer on top of the rule engine (unsupervised outlier detection on event volume/patterns) — explicitly a v2 feature, don't let it block v1

---

*Attach this file alongside your kickoff prompt when you start the Claude Code session — same pattern as the Metadata Analyzer.*

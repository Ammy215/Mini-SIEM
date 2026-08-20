# 🛡️ MINI_SIEM_CONTEXT.md — Master Build File

> Paste this whole file into Claude Code as the project reference before building.
> It pairs with your global `CLAUDE_CONTEXT.md` — all the rules there (no Docker,
> phases with tests, real live data, no mock data in the product, JetBrains Mono
> for technical values, dark cyber theme) still apply here.

**Repo:** https://github.com/Ammy215/Mini-SIEM.git (empty — Claude Code generates README, .gitignore, LICENSE, everything)

---

## 🧠 What this project is (plain English)

A **SIEM** (Security Information & Event Management) is the box a security team
uses to watch everything at once. Every machine and app writes *logs* — a line
each time someone logs in, each web request, each firewall block. Alone, those
lines are noise. The SIEM (1) collects them, (2) rewrites them into one common
shape, (3) runs rules that say "this pattern = attack," and (4) raises an alert
when it sees one. Splunk / Elastic Security / Microsoft Sentinel are the real
ones. This is a **Mini** version — same skeleton, small enough to fully build
and understand.

**The pipeline (memorize this):**

```
1. Log sources        SSH, web server, firewall, your own test attacks
        ↓
2. Collector          an API endpoint that receives raw log lines
        ↓
3. Parse + normalize  raw text → structured events (one common schema)
        ↓
4. Store              PostgreSQL — one indexed events table
        ↓
5. Detection engine   rules run over events → attack found   ← THE HEART
        ↓
6. Alerts + dashboard live feed, incidents, search, IP intel
```

**The core feature that must work:** the detection engine (stage 5). Everything
else exists to feed it or display what it finds. If detection is accurate and
fast, the project succeeds.

---

## 🎯 The problem it solves — what it must catch

Two detection styles, both required:

**A) Threshold / behavioural** — counting over a time window (plain SQL):
| Attack | Rule | MITRE |
|---|---|---|
| Brute force | >10 failed logins, one IP, 5 min | T1110 |
| Credential stuffing | ≥5 distinct usernames, one IP, 10 min | T1110.004 |
| Port scan | ≥15 distinct dest ports, one IP, 5 min | T1046 |
| Password spray | one username, many IPs | T1110.003 |

**B) Signature / pattern** — matching known-bad shapes in a field (Sigma-style rules):
| Attack | Match on | MITRE |
|---|---|---|
| SQL injection | `' OR 1=1`, `UNION SELECT`, `--` in url/query | T1190 |
| XSS | `<script>`, `onerror=` in params | T1059.007 |
| Path traversal | `../`, `/etc/passwd` in url | T1083 |
| Scanner tools | UA contains `sqlmap` / `nikto` / `nmap` | T1595 |

Every detection is tagged with a **MITRE ATT&CK** technique ID and produces a
weighted **threat score (0–100)**. That ATT&CK tagging is the single most
interview-valuable detail in the whole build — it's what real SOC tools do.

---

## ⚙️ Tech stack (LOCKED — do not substitute)

```
Backend:    Python + FastAPI + Uvicorn
Database:   PostgreSQL ONLY   (no OpenSearch, no Mongo, no Redis in v1)
Validation: Pydantic v2
DB access:  SQLAlchemy (async) OR asyncpg + raw SQL — pick one, stay consistent
Auth:       own JWT (access + refresh) + bcrypt + RBAC   (NOT Supabase Auth)
Jobs:       FastAPI background tasks + a simple interval scheduler (no Celery v1)
HTTP:       httpx (async) for threat-intel API calls
Frontend:   React 18 + Vite + Tailwind + shadcn/ui + Recharts + Framer Motion
Data fetch: TanStack React Query + Axios
Icons/font: Lucide React, JetBrains Mono (all IPs/hashes/CVEs), Inter (UI)
Deploy:     Vercel (frontend) + Render (backend) + Render Postgres (db)
CI:         GitHub Actions (test on every push)
```

**Why Postgres, not OpenSearch** (say this in an interview): "My log volume
didn't justify a dedicated search cluster. Postgres with proper indexes and
built-in full-text search covered it, and I can explain exactly when I'd add
OpenSearch — huge volume, fuzzy full-text at scale." Understanding *why not* is
stronger than bolting it on.

---

## 🔑 API keys — all free, all server-side only

| Provider | Purpose | Free signup |
|---|---|---|
| AbuseIPDB | IP reputation / abuse score | abuseipdb.com/register |
| AlienVault OTX | Threat pulses / IOC match | otx.alienvault.com/accounts/register |
| IPInfo | Geolocation, ASN, ISP | ipinfo.io/signup |
| VirusTotal | Hash / domain / URL rep | virustotal.com/gui/join-us |
| NIST NVD | CVE feed (key optional, raises rate limit) | nvd.nist.gov/developers/request-an-api-key |
| Groq (optional) | Free-tier LLM for alert summaries | console.groq.com |

**Hard rule:** every external API call happens in the **backend only**. The
frontend never sees a key. Keys live only in the server environment. AI is
optional — skip it entirely in v1 if you want zero AI surface.

---

## 📄 Complete `.env` template

**backend/.env.example**
```
# ---- App ----
APP_ENV=development
SECRET_KEY=change_me_to_a_long_random_string
JWT_ACCESS_TTL_MIN=30
JWT_REFRESH_TTL_DAYS=7
FRONTEND_ORIGIN=http://localhost:5173

# ---- Database ----
DATABASE_URL=postgresql://siem:siem@localhost:5432/mini_siem

# ---- Admin seed (used ONCE by scripts/seed_admin.py) ----
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=change_me_strong_password

# ---- Threat intel (all free) ----
ABUSEIPDB_API_KEY=
OTX_API_KEY=
IPINFO_TOKEN=
VIRUSTOTAL_API_KEY=
NVD_API_KEY=

# ---- Optional AI ----
GROQ_API_KEY=

# ---- DEV-ONLY attack lab. MUST stay false/unset in production ----
ENABLE_ATTACK_LAB=false
```

**frontend/.env.example**
```
VITE_API_BASE_URL=http://localhost:8000
```

---

## 🗄️ Database schema (raw PostgreSQL — `backend/sql/schema.sql`)

```sql
CREATE EXTENSION IF NOT EXISTS pgcrypto;   -- for gen_random_uuid()

-- ---------- users & RBAC ----------
CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  full_name TEXT,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  failed_login_count INT NOT NULL DEFAULT 0,
  locked_until TIMESTAMPTZ,
  last_login_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE roles (
  id SERIAL PRIMARY KEY,
  name TEXT UNIQUE NOT NULL            -- admin | analyst | viewer
);

CREATE TABLE user_roles (
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  role_id INT  REFERENCES roles(id)  ON DELETE CASCADE,
  PRIMARY KEY (user_id, role_id)
);

-- ---------- normalized events ----------
CREATE TABLE events (
  id BIGSERIAL PRIMARY KEY,
  event_time  TIMESTAMPTZ NOT NULL,
  ingested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  source_type TEXT NOT NULL,          -- ssh | nginx | apache | syslog | app | firewall
  source_ip   INET,
  dest_ip     INET,
  dest_port   INT,
  username    TEXT,
  action      TEXT,                   -- login_failed | login_success | request | blocked ...
  status_code INT,
  method      TEXT,
  url         TEXT,
  user_agent  TEXT,
  country     TEXT,
  raw_message TEXT,
  raw         JSONB
);
CREATE INDEX idx_events_time   ON events (event_time DESC);
CREATE INDEX idx_events_src    ON events (source_ip);
CREATE INDEX idx_events_action ON events (action);
CREATE INDEX idx_events_fts    ON events USING GIN (to_tsvector('english', coalesce(raw_message,'')));

-- ---------- detection rules ----------
CREATE TABLE rules (
  id SERIAL PRIMARY KEY,
  rule_key TEXT UNIQUE NOT NULL,
  title TEXT NOT NULL,
  description TEXT,
  rule_type TEXT NOT NULL,            -- threshold | signature
  severity TEXT NOT NULL,             -- low | medium | high | critical
  mitre_technique TEXT,               -- e.g. T1110
  definition JSONB NOT NULL,          -- threshold params OR match conditions
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------- incidents (grouped alerts) ----------
CREATE TABLE incidents (
  id BIGSERIAL PRIMARY KEY,
  title TEXT NOT NULL,
  source_ip INET,
  severity TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',
  alert_count INT NOT NULL DEFAULT 0,
  first_seen TIMESTAMPTZ,
  last_seen  TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------- alerts ----------
CREATE TABLE alerts (
  id BIGSERIAL PRIMARY KEY,
  rule_id INT REFERENCES rules(id),
  incident_id BIGINT REFERENCES incidents(id),
  title TEXT NOT NULL,
  severity TEXT NOT NULL,
  mitre_technique TEXT,
  source_ip INET,
  threat_score INT,                   -- 0-100
  status TEXT NOT NULL DEFAULT 'open', -- open | acknowledged | resolved | false_positive
  evidence JSONB,                     -- the events/counts that triggered it
  acknowledged_by UUID REFERENCES users(id),
  acknowledged_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_alerts_created ON alerts (created_at DESC);
CREATE INDEX idx_alerts_status  ON alerts (status);

-- ---------- enrichment cache ----------
CREATE TABLE ioc_cache (
  id BIGSERIAL PRIMARY KEY,
  indicator TEXT NOT NULL,
  indicator_type TEXT NOT NULL,       -- ip | domain | hash | url
  provider TEXT NOT NULL,             -- abuseipdb | otx | ipinfo | virustotal
  data JSONB NOT NULL,
  cached_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  UNIQUE (indicator, provider)
);

-- ---------- audit log ----------
CREATE TABLE audit_log (
  id BIGSERIAL PRIMARY KEY,
  user_id UUID REFERENCES users(id),
  action TEXT NOT NULL,
  detail JSONB,
  ip_address INET,
  user_agent TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO roles (name) VALUES ('admin'),('analyst'),('viewer')
  ON CONFLICT DO NOTHING;
```

---

## 🧮 Detection engine design

**Threat scoring** (`backend/detection/scorer.py`):
```python
THREAT_WEIGHTS = {
    "brute_force_confirmed":   30,
    "credential_stuffing":     20,
    "port_scan":               15,
    "sqli_pattern":            25,
    "xss_pattern":             15,
    "path_traversal":          20,
    "known_bad_ip":            20,   # AbuseIPDB score > 80
    "otx_pulse_match":         15,
    "scanner_user_agent":      15,
    "after_hours":              5,
    "foreign_geo":              5,
}
SEVERITY_BANDS = {(0,25):"low",(25,50):"medium",(50,75):"high",(75,101):"critical"}
```

**Threshold rules** run on an interval (e.g. every 30–60s) as SQL over the last
N minutes of `events`, grouped by `source_ip`. Each match → an `alert` with the
triggering events stored in `evidence`.

**Signature rules** load from YAML in `backend/rules_yaml/`. Example shape:
```yaml
title: SQL Injection Attempt in HTTP Request
rule_key: sqli-http-001
rule_type: signature
severity: high
mitre: T1190
logsource: nginx
detection:
  field: url
  contains: ["' OR 1=1", "UNION SELECT", "' OR '1'='1", "--", "/*"]
  condition: any
```
On startup, YAML rules are synced into the `rules` table so they're editable in
the UI and toggleable per rule.

**Correlation → incidents:** alerts from the same `source_ip` inside a time
window collapse into one `incident` with a first_seen/last_seen timeline, so one
attacker campaign is one incident, not 50 separate alerts.

---

## 🔐 Auth & admin model (answering "what is admin / how do I log in")

- **No hardcoded credentials, ever.** Passwords are bcrypt-hashed.
- **Admin is created once** by `scripts/seed_admin.py`, which reads
  `ADMIN_EMAIL` + `ADMIN_PASSWORD` from env, creates that user, and assigns the
  `admin` role. You run it a single time after the DB is up.
- **You log in** at `/login` with that email + password → you get a JWT →
  the admin role unlocks the Admin panel. Simple as that.
- **Roles:**
  - `admin` — everything: user management, rule management, audit log, all data
  - `analyst` — investigations, run detections, manage own alerts, view all events
  - `viewer` — read-only: dashboards, alerts, events, no changes
- Failed logins increment a counter; too many → temporary lock (`locked_until`).
- Every sensitive action writes to `audit_log` with IP + user agent.

---

## 🛡️ Security hardening checklist (non-negotiable)

- All third-party API calls backend-only; no key ever reaches the browser.
- JWT: short access token + refresh; bcrypt; timing-safe password compare.
- RBAC dependency on every protected route; permission checked server-side.
- Rate limits: auth strict (e.g. 10/15min), ingest capped, global ceiling → 429.
- Pydantic validation before any external call; reject private/reserved IPs from enrichment.
- **Parameterized SQL everywhere** — a SIEM with its own SQLi would be a disaster.
- Security headers (CSP, HSTS, X-Content-Type-Options) via middleware; CORS locked to `FRONTEND_ORIGIN`.
- Secrets only in env; verify with the dev-tools leak check after deploy (Network tab + Sources — nothing sensitive client-side).
- The attack-lab routes (below) are **gated behind `ENABLE_ATTACK_LAB`, default off, never enabled in production**.

---

## 🧪 The self-attack lab — and why it can't hurt your machine

You asked whether attacking your own app is dangerous. It isn't, because of how
it's built:

- The vulnerable "practice" routes (a fake login you can brute-force, a param
  with a SQLi/XSS shape) live under `routers/attack_lab.py` and **only register
  when `ENABLE_ATTACK_LAB=true`** — which is only ever true on your local dev
  machine. In the deployed build the code path doesn't even load.
- You attack **those local routes** with Burp Suite (Community is free): repeater,
  intruder for the brute-force, a SQLi-shaped request. Your app logs that traffic
  as events, and your **detection engine catches it** and raises the matching alert.
- It's your own app logging your own test traffic on localhost. Nothing is exposed
  to the internet, nothing gains control of anything. It's a firing range, not a
  live weapon.

This loop is also your best demo: "I attacked my own SIEM with Burp and it
detected brute force (T1110), a port scan (T1046), and SQL injection (T1190) in
real time."

---

## ✅ Testing strategy (three layers + CI)

1. **Unit** — the detection logic in isolation, using **fixture log data**. This
   is the one correct place for synthetic data: you can't wait for a real
   brute-force to test a brute-force rule. That's not "fake data in the product,"
   it's how every real test suite works. Test: feed a crafted burst → assert the
   right alert with the right count + MITRE tag.
2. **Integration** — real Postgres + real parser + real (or recorded) API calls.
   Test: upload a real sample log file → events normalized correctly → detection
   pass produces expected alerts.
3. **End-to-end / live** — the Burp self-attack loop against the running app,
   plus a browser walk of the main user flow (login → dashboard → alert appears).

**CI** — `.github/workflows/ci.yml` runs the suite on every push; a red run
blocks nothing from your machine but tells you instantly what broke.

---

## 📁 Folder structure

```
Mini-SIEM/
├─ README.md  LICENSE  .gitignore
├─ .github/workflows/ci.yml
├─ backend/
│  ├─ .env.example  requirements.txt
│  ├─ main.py  config.py  database.py
│  ├─ auth/        (jwt.py, password.py, rbac.py, deps.py)
│  ├─ models/      (pydantic schemas)
│  ├─ routers/     (auth, ingest, events, rules, alerts, incidents,
│  │                enrich, stats, admin, health, attack_lab)
│  ├─ parsers/     (ssh.py, nginx.py, syslog.py, app_json.py)
│  ├─ detection/   (threshold.py, signature.py, scorer.py, scheduler.py, correlate.py)
│  ├─ enrichment/  (abuseipdb.py, otx.py, ipinfo.py, virustotal.py, cache.py)
│  ├─ rules_yaml/  (*.yml signature rules)
│  ├─ scripts/     (migrate.py, seed_admin.py, seed_rules.py)
│  ├─ sql/         (schema.sql)
│  └─ tests/       (unit/, integration/, fixtures/)
└─ frontend/
   ├─ .env.example  package.json  index.html  vite.config.js
   └─ src/
      ├─ main.jsx  App.jsx
      ├─ api/        (axios client + react-query hooks)
      ├─ components/ (ui/, layout/, charts/)
      ├─ pages/      (Login, Dashboard, Events, Alerts, Incidents,
      │               Rules, IpIntel, AttackLab, Admin, Settings)
      └─ styles/     (theme.css)
```

---

## 🔌 API endpoints

```
# auth
POST   /api/auth/register
POST   /api/auth/login
POST   /api/auth/logout
POST   /api/auth/refresh
GET    /api/auth/me

# ingest + parse
POST   /api/ingest              ← agent/app posts events (single or batch)
POST   /api/logs/upload         ← upload a raw log file, parse + normalize

# events
GET    /api/events              ← filter, paginate, full-text search
GET    /api/events/{id}

# rules + detection
GET    /api/rules
POST   /api/rules
PUT    /api/rules/{id}
POST   /api/rules/{id}/toggle
POST   /api/detect/run          ← manually trigger a detection pass

# alerts + incidents
GET    /api/alerts
GET    /api/alerts/{id}
PUT    /api/alerts/{id}          ← acknowledge / change status
GET    /api/incidents
GET    /api/incidents/{id}

# enrichment
GET    /api/enrich/ip/{ip}

# dashboard
GET    /api/stats/dashboard
GET    /api/stats/timeline
GET    /api/stats/top-attackers

# admin
GET    /api/admin/users
POST   /api/admin/users
PUT    /api/admin/users/{id}
POST   /api/admin/users/{id}/suspend
GET    /api/admin/audit

# system
GET    /api/health
GET    /api/setup/validate      ← checks DB + which API keys are present/valid
```

Live feed: start with **React Query polling** (every 5–10s) — simplest and
plenty good. Add a WebSocket `/ws/live` later only if you want true push.

---

## 🎨 Frontend

Pages: Login, Dashboard (counts + attack timeline + top attackers + recent
alerts + live feed), Events explorer (search/filter table), Alerts (severity
cards, acknowledge/investigate), Incidents (grouped + timeline), Rules (list,
toggle, edit — analyst/admin), IP Intel (enrichment profile), Attack Lab
(dev-only), Admin (users + audit log), Settings (API-key health, profile).

Design system — your standard dark cyber theme:
```css
--bg-primary:#050d1a; --bg-secondary:#0a1628; --bg-tertiary:#0f1e35; --bg-border:#1a2d4a;
--accent-cyan:#00d4ff; --accent-green:#00ff88; --accent-amber:#ffb800;
--accent-red:#ff3366; --accent-purple:#8b5cf6;
--text-primary:#e2e8f0; --text-secondary:#64748b;
--font-mono:'JetBrains Mono'; --font-sans:'Inter';
```
Verdict colors: LOW→green, MEDIUM→amber, HIGH/CRITICAL→red (critical pulses),
UNKNOWN→gray. IPs / ports / rule IDs / MITRE tags → JetBrains Mono always.

---

## 🧭 Model, effort, and tooling to use at each phase

Two honest caveats before this table: Claude Code's exact effort-level names and
defaults have changed more than once this year, and I can't see which MCP
connectors you have enabled — so treat the effort column as current guidance to
sanity-check against Claude Code's own docs when you get there, and treat the
tooling column as "search for this before the phase," not "assume it's there."
The underlying judgment (low effort for scaffolding, high effort + plan mode for
anything security- or logic-critical) will stay true even if the exact setting
names move again.

| Phase | Model / effort | Plan mode? | MCP / connector / skill |
|---|---|---|---|
| 0 — Repo hygiene | Sonnet, standard effort | No | GitHub connector (or `gh` CLI) to create/push the repo instead of manual upload |
| 1 — Foundation | Sonnet, standard effort | Optional | Once Postgres exists, a DB connector for direct schema verification beats dashboard round-trips |
| 2 — Auth + RBAC | Sonnet, **high effort** (security-critical) | **Yes — review the plan before any code** | none needed |
| 3 — Ingestion + parsing | Sonnet, standard effort | No | none needed |
| 4 — Detection: threshold | Sonnet, **high effort** (this is the core feature) | **Yes** | none needed |
| 5 — Detection: signature | Sonnet, **high effort** | **Yes** | none needed |
| 6 — Enrichment | Sonnet, standard effort | No | none needed |
| 7 — Incidents / correlation | Sonnet, medium–high effort | Optional | none needed |
| 8 — Frontend core | Sonnet, standard effort | No | Run `npx shadcn@latest init` here, real foundation — do NOT hand-roll shadcn-style components, per `frontend-resources-reference.md`; retrofitting later is much harder than starting right |
| 9 — Frontend polish + live feed | Sonnet, standard effort | No | Optional: Realtimecolors.com once, to sanity-check the existing dark-cyber palette's contrast before it's baked into every component |
| 10 — Attack Lab + self-attack | Sonnet, **high effort** | **Yes** | Playwright MCP (official, free) once you're driving the browser through login/attack flows repeatedly — replaces scratch test scripts |
| 11 — Hardening + full test suite + CI | Sonnet, **high effort** | **Yes** | Playwright MCP (carried over from Phase 10); Burp Suite MCP if you have Burp Community, for the SQLi/XSS/rate-limit sweep |
| 12 — Deployment | Sonnet, medium–high effort | Optional | Vercel MCP (official, free on Hobby) for the frontend deploy/env vars/logs step; Render has no official MCP as of this writing — verify before assuming one exists, otherwise use its dashboard/CLI |

**Rule of thumb if you want one sentence**: plan mode + higher effort for anything
where a wrong answer is expensive to find later (auth, the detection logic
itself, security hardening) — default effort for anything routine and easily
re-checked (scaffolding, parsers, polish). Don't add a connector "just in case" —
only when the phase actually creates the repeated, felt pain point it solves
(per `mcp-connectors-plugins-skills-reference.md`'s verification checklist);
search for it fresh when you reach that phase rather than trusting this table
blindly, since new options may exist by then.

---

## 🧭 Build phases (each has a test gate — do NOT move on until it passes)

**Phase 0 — Repo hygiene.** Init repo, README, `.gitignore` (env, venv,
node_modules), LICENSE (MIT), `.env.example` (both), folder skeleton, CI stub.
*Test:* repo clones clean, structure present, `git status` shows no secrets.

**Phase 1 — Foundation.** FastAPI app, config loader, Postgres connection,
`schema.sql` applied via `scripts/migrate.py`, `/api/health`,
`/api/setup/validate`. *Test:* health green, all tables exist, validate lists key status.

**Phase 2 — Auth + RBAC.** register/login/logout/refresh/me, JWT, bcrypt,
roles, `seed_admin.py`, audit log, lockout. *Test:* register→login→hit a
protected route; viewer blocked from an admin route; admin seed logs in.

**Phase 3 — Ingestion + parsing.** `/api/ingest`, `/api/logs/upload`, SSH +
nginx + syslog + app-JSON parsers → normalized `events`. *Test:* upload real
sample logs → events appear with correct fields; counts match the file.

**Phase 4 — Detection: threshold.** brute-force, cred-stuffing, port-scan on a
scheduler → alerts with MITRE tags + score. *Test:* feed a fixture brute-force
burst → one alert, right count, T1110.

**Phase 5 — Detection: signature.** YAML loader + `seed_rules.py`, SQLi/XSS/
traversal/scanner-UA rules, scoring. *Test:* feed matching lines → correct
rules fire, correct scores.

**Phase 6 — Enrichment.** AbuseIPDB/OTX/IPInfo on alert IPs, `ioc_cache`,
private-IP block. *Test:* enrich a known-bad IP (live) → data returns; second
call hits cache; private IP rejected.

**Phase 7 — Incidents.** correlate alerts by IP/time into incidents + timeline.
*Test:* several related alerts collapse into one incident.

**Phase 8 — Frontend core.** Set up a **real shadcn foundation first**
(`npx shadcn@latest init`, real `components.json`, Radix as a dependency) —
not hand-rolled "shadcn-style" components like your earlier projects. This is
the single decision that determines whether component libraries drop in
cleanly later or need a full retrofit. Then: login, dashboard, events
explorer, alerts — wired to the real API. *Test:* full flow in the browser on
real data.

**Phase 9 — Frontend polish + live feed.** incidents, rules mgmt, IP intel,
admin panel, settings, polling live feed, theme + Framer Motion. Optionally
run the existing dark-cyber palette through Realtimecolors.com once to confirm
contrast before it's baked into every component. *Test:* every page works and
is responsive.

**Phase 10 — Attack Lab + self-attack.** gated vulnerable routes, Burp workflow,
prove detection. *Test:* run each attack → the matching alert appears.

**Phase 11 — Hardening + full test suite + CI.** rate limits, headers, audit
coverage, unit+integration+e2e, GitHub Actions green. *Test:* whole suite passes
in CI on push.

**Phase 12 — Deployment.** (below). *Test:* live URL works end-to-end; dev-tools
secret-leak check passes.

Commit after every phase with a clear prefix: `feat:`, `fix:`, `security:`,
`test:`, `chore:`.

---

## 🚀 Deployment (Vercel + Render + Render Postgres — free)

**Backend + DB on Render**
1. Push everything to the GitHub repo.
2. Render → New → **PostgreSQL** (free) → copy the **Internal Database URL**.
   *(Verify Render's current free-Postgres terms at signup — free databases have
   had time limits before. If that's a problem, **Neon** offers a durable free
   Postgres tier as a drop-in fallback — same `DATABASE_URL` idea.)*
3. Render → New → **Web Service** → connect the repo → **Root Directory:** `backend`
   → Build: `pip install -r requirements.txt` → Start:
   `uvicorn main:app --host 0.0.0.0 --port $PORT`.
4. Add env vars (from `.env.example`): `DATABASE_URL` = the internal URL,
   `SECRET_KEY`, the API keys, `FRONTEND_ORIGIN` = your Vercel URL (fill after
   step 7), `APP_ENV=production`. Leave `ENABLE_ATTACK_LAB` unset.
5. In Render Shell (one-off): `python scripts/migrate.py && python scripts/seed_rules.py && python scripts/seed_admin.py`.
6. Visit `https://<service>.onrender.com/api/health` → expect green.
   *(Free web services sleep when idle; the first hit after a nap takes ~30–50s.
   That's normal on free tier, not a bug.)*

**Frontend on Vercel**
7. Vercel → New Project → import the repo → **Root Directory:** `frontend` →
   framework auto-detects Vite → env var `VITE_API_BASE_URL` = your Render backend
   URL → Deploy → get `https://<app>.vercel.app`.
8. Back in Render, set `FRONTEND_ORIGIN` to that Vercel URL (CORS), redeploy.

**After deploy — what you should see / do**
- Open the Vercel URL → login page loads.
- Log in with `ADMIN_EMAIL` / `ADMIN_PASSWORD` → dashboard loads, admin panel visible.
- Upload a sample log → events appear → run detection → alerts show.
- Dev-tools check: Network tab + Sources → confirm no API key or DB URL is
  anywhere client-side. Only `VITE_API_BASE_URL` (a public URL) should appear.

---

## 💻 Run locally (Windows)

```bash
# backend
cd backend
python -m venv venv && venv\Scripts\activate
pip install -r requirements.txt --break-system-packages
copy .env.example .env          # then fill it in
python scripts/migrate.py
python scripts/seed_rules.py
python scripts/seed_admin.py
uvicorn main:app --reload --port 8000    # → http://localhost:8000/docs

# frontend (new terminal)
cd frontend
npm install
copy .env.example .env
npm run dev                     # → http://localhost:5173
```

---

## 🔮 Future upgrades — OUT OF SCOPE

`FUTURE_UPGRADES.md` records deliberate v2 ideas and accepted limitations
(currently: multi-tenancy, and session/token revocation). Everything in that
file is explicitly **not** in scope — do not implement any of it unless asked
directly. Read it only if a request touches one of those areas.

---

## 🚫 / ✅ Rules carried from CLAUDE_CONTEXT

No Docker. No mock data in the product (fixtures in unit tests only). Phase by
phase, test before moving on, fix before advancing. Explain *why* before
generating code. Real live data from real APIs. Never hardcode or expose keys.
Commit every phase to GitHub. Warn me now if something will break later.

---

## 📋 PASTE THIS INTO CLAUDE CODE TO START

```
Read MINI_SIEM_CONTEXT.md in full — it's the complete spec for this project.
Also honor my global CLAUDE_CONTEXT.md rules (no Docker, phases with tests,
real live data, no mock data in the product, explain before coding).

We build in the numbered phases from the spec, one at a time. For EACH phase:
1. First tell me what you're about to build and why — the key decisions, in
   plain terms — and wait for my "go" before writing code.
2. Then implement only that phase.
3. Then give me the exact command(s) to run its test gate, and confirm it
   passes on real data before we continue.
4. Then commit to https://github.com/Ammy215/Mini-SIEM.git with a clear
   message (feat:/fix:/security:/test:/chore:).

Start now with Phase 0 (repo hygiene): generate README, .gitignore, LICENSE
(MIT), both .env.example files, the full folder skeleton, and the CI stub —
then show me the tree and the Phase 0 test before Phase 1.

Hold yourself to "verified, not assumed" the whole way — test for real and tell
me honestly when something doesn't work instead of rounding up to "done."
```
```
```

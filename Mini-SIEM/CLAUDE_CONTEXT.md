# 🧠 CLAUDE_CONTEXT.md — Master Session File
> Paste this entire file as your FIRST MESSAGE in any new Claude session.
> Claude will have full context of who you are, all your projects, your 
> style, and exactly how to help you — no re-explaining anything.

---

## ⚡ How to Start Every Session

**Paste this file → Claude responds with:**
```
Got it. Full context loaded. All projects, stack, style — I know everything.
What are we working on today?
```
Then just tell me what you need. That's it.

---

## 👤 Who I Am

- Cybersecurity student learning by building real projects
- NOT an expert — I need clear explanations, not textbook answers
- I learn by doing — build first, understand as I go
- I use VS Code with Claude Code extension for all building
- I use a separate Claude account for guidance and prompts
- Talk to me like a **senior dev mentoring a junior** — friendly, 
  direct, honest, no over-explaining things I already know
- If I am doing something wrong or backwards — tell me directly

---

## 💻 My Development Setup

| Thing | Detail |
|-------|--------|
| Editor | VS Code + Claude Code extension (Claude Sonnet 4.5) |
| OS | Windows |
| Python packages | `pip install x --break-system-packages` |
| JS packages | npm |
| Docker | **NEVER** — I configure everything manually |
| Terminal | VS Code integrated terminal |
| Git | GitHub — one repo per project |

---

## 📊 My Skill Level

| Technology | Level |
|------------|-------|
| Python | Comfortable |
| Flask | Comfortable |
| PostgreSQL basics | Comfortable |
| FastAPI | Currently learning |
| MongoDB | Currently learning |
| React + Vite | Currently learning |
| Node.js + Express | Currently learning |
| Supabase | Currently learning |
| Python Sockets | Currently learning |
| Threat Intelligence | Currently learning |

---

## 🏗️ My Build Philosophy

1. **Phases not all at once** — one phase at a time, test before next
2. **No mock data anywhere** — everything uses real live APIs and real data
3. **No Docker ever** — manual configuration for deep learning
4. **Fix before moving** — if something is broken, fix it before next phase
5. **Understand everything** — explain why, not just generate code
6. **Real live data** — no fake JSON, no dummy datasets, no hardcoded samples

---

## 🔑 API Keys I Use (No Actual Keys Here — Just References)

| Provider | Purpose | Free Signup |
|----------|---------|-------------|
| AbuseIPDB | IP reputation | https://www.abuseipdb.com/register |
| AlienVault OTX | Threat pulses | https://otx.alienvault.com/accounts/register |
| IPInfo | Geolocation | https://ipinfo.io/signup |
| NIST NVD | CVE feed | https://nvd.nist.gov/developers/request-an-api-key |
| VirusTotal | Hash/URL/domain | https://www.virustotal.com/gui/join-us |
| OpenAI | AI analysis | https://platform.openai.com |

---

## 🎨 My Design System (All Cybersecurity Projects)

```css
/* Dark Cybersecurity Theme — use this on ALL projects */
--bg-primary:     #050d1a    /* deepest navy — page background */
--bg-secondary:   #0a1628    /* card backgrounds */
--bg-tertiary:    #0f1e35    /* elevated surfaces, hover states */
--bg-border:      #1a2d4a    /* all borders */

--accent-cyan:    #00d4ff    /* primary accent, links, active */
--accent-green:   #00ff88    /* safe, success, low risk */
--accent-amber:   #ffb800    /* warning, suspicious, medium risk */
--accent-red:     #ff3366    /* danger, critical, high risk */
--accent-purple:  #8b5cf6    /* AI features, special actions */

--text-primary:   #e2e8f0
--text-secondary: #64748b
--text-muted:     #334155

--font-mono:      'JetBrains Mono', monospace  /* IPs, hashes, code */
--font-sans:      'Inter', system-ui           /* all UI text */
```

### Risk/Verdict Colors
```
SAFE / LOW        → green  #00ff88
SUSPICIOUS/MEDIUM → amber  #ffb800
HIGH RISK         → red    #ff3366
CRITICAL          → red    #ff3366 + pulse animation
UNKNOWN           → gray   #64748b
```

### Typography Rules
- All IPs, hashes, CVE IDs, domains → JetBrains Mono always
- Metric numbers → Inter weight 700
- Navigation and labels → Inter weight 400–500
- No text below 12px anywhere

---

## 🛠️ Common Commands Reference

```bash
# ── Python Backend ────────────────────────────────
uvicorn backend.main:app --reload --port 8000
pip install -r requirements.txt --break-system-packages
python -m venv venv && venv\Scripts\activate      # Windows venv

# ── Streamlit Dashboard ───────────────────────────
streamlit run dashboard/app.py

# ── MongoDB ───────────────────────────────────────
mongod --dbpath /data/db
mongosh
use log_analyzer
db.logs.countDocuments()

# ── Node.js Backend ───────────────────────────────
node server.js
node --watch server.js                             # auto-restart
npm run dev

# ── React Frontend ────────────────────────────────
cd frontend && npm run dev                         # http://localhost:5173
npx shadcn@latest init
npx shadcn@latest add button card badge table dialog tabs tooltip select

# ── Test APIs ─────────────────────────────────────
curl http://localhost:8000/docs                    # FastAPI Swagger
curl http://localhost:8000/api/health
curl http://localhost:3001/api/health              # Node backend
```

---

## 📁 How I Like Prompts Generated

When I say **"generate a prompt"** or **"make a prompt for this"**:

- Make it **complete and paste-ready** — I copy it and paste it directly into Claude Code
- Include: folder structure, all file names, full implementation logic, 
  exact commands to run, phase-by-phase build order
- Every phase must have a **test** — how to verify it works before moving on
- Include **all dependencies** in requirements.txt or package.json
- Include **complete .env template** with every variable
- Include **database schema** as raw SQL or code
- Include **all API endpoint definitions**
- End with **exact prompt text to paste into Claude Code**

---

## 🚀 My Frontend Stack (All New Projects)

```
React 18 + Vite
Tailwind CSS (dark cybersecurity theme above)
shadcn/ui (full component suite)
Framer Motion (animations)
Recharts (all charts and visualizations)
Lucide React (icons)
TanStack React Query (data fetching)
React Router v6 (navigation)
Axios (API calls)
date-fns (date formatting)
Sonner (toast notifications)
react-dropzone (file uploads where needed)
JetBrains Mono font (all code/hash/IP display)
```

## ⚙️ My Backend Stack (Python Projects)

```
FastAPI (NOT Flask)
Motor (async MongoDB driver) OR SQLAlchemy (PostgreSQL)
Pydantic v2 (data validation)
python-dotenv (env vars)
uvicorn (ASGI server)
httpx / aiohttp (async HTTP calls)
```

## ⚙️ My Backend Stack (Node.js Projects)

```
Express.js
Supabase JS client v2
Helmet (security headers)
express-rate-limit
express-validator
Winston (logging)
node-cron (scheduled tasks)
Axios (external API calls)
dotenv
```

---

## 📦 Projects Already Built

---

### 🔍 Project 1 — Metadata & File Intelligence Analyzer

**What:** Cybersecurity tool that analyzes uploaded files and generates 
security reports — metadata, hashing, keyword detection, entropy analysis, 
risk scoring.

**Status:** Backend complete. Frontend being rebuilt from scratch.

**Tech Stack:**
```
Backend:  Python + FastAPI
Database: PostgreSQL (SQLite local dev)
ORM:      SQLAlchemy
Analysis: hashlib, python-magic, Pillow, pdfplumber, python-docx, pefile, math
Frontend: React 18 + Vite + Tailwind + shadcn/ui + Recharts + Framer Motion
```

**Supported File Types:**
PDF, DOCX, TXT, JPG/PNG (EXIF), ZIP, EXE, CSV, JSON

**Core Analysis Features:**
- SHA256 + MD5 + SHA1 hashing (with copy button)
- Shannon entropy calculation + byte distribution chart
- Suspicious keyword matching with regex (CRITICAL/HIGH/MEDIUM/LOW)
- EXIF metadata extraction (including GPS flag)
- PE header analysis for EXE files (pefile)
- Risk scoring engine (0–100 weighted)
- Verdict: SAFE / SUSPICIOUS / HIGH RISK / CRITICAL
- Security report generation with PDF export
- VirusTotal SHA256 link button

**Risk Scoring Weights:**
```python
THREAT_WEIGHTS = {
    "critical_keyword_match":  +25,
    "high_keyword_match":      +15,
    "medium_keyword_match":    +8,
    "yara_rule_match":         +30,
    "high_entropy":            +20,   # entropy > 7.5
    "medium_entropy":          +10,   # entropy 6.5–7.5
    "dangerous_extension":     +20,   # .exe .bat .ps1 .vbs
    "hidden_metadata":         +10,
    "embedded_urls":           +10,
    "gps_data_found":          +10,
}
```

**Frontend Pages:** Upload & Analyze, Scan History, Statistics, About

**Database Tables:** uploaded_files, metadata_analysis, suspicious_matches, entropy_results

**API Endpoints:**
```
POST   /api/upload
POST   /api/analyze/{file_id}
GET    /api/report/{file_id}
GET    /api/report/{file_id}/pdf
GET    /api/history
GET    /api/stats
GET    /api/health
```

**Known Issues (Being Fixed):**
- Entropy score returning 0
- Hash generation returning empty
- Keyword scanner not finding matches
- Metadata not extracting for all file types
- Risk score not calculating correctly
- Pipeline not fully wired end to end

**Deployment:**
- Frontend → Vercel
- Backend → Railway or Render
- Database → Supabase PostgreSQL
- Files → Cloudflare R2

---

### 📊 Project 2 — Intelligent Log Analyzer

**What:** Security log analysis platform that parses, analyzes, and 
visualizes attack patterns from real system logs.

**Status:** All 5 phases complete. Working.

**Tech Stack:**
```
Backend:   Python + FastAPI
Database:  MongoDB (Motor async driver)
Dashboard: Streamlit (multi-page, 5 pages)
Charts:    Plotly
Data:      Pandas + NumPy
HTTP:      Requests + Aiohttp
AI:        OpenAI API + LangChain
```

**Log Parsers Built:**
- SSH auth.log parser
- Apache access.log parser
- Windows Event Log parser
- Generic syslog parser

**Core Features:**
- Brute force detection (>10 attempts in 5 min)
- Port scan detection
- Credential stuffing detection
- Threat scoring engine (weighted 0–100)
- AbuseIPDB integration
- AlienVault OTX integration
- IP geolocation with world map (Plotly choropleth)
- AI-generated threat reports via LangChain
- Pandas aggregation pipelines for analytics

**Threat Score Weights:**
```python
THREAT_WEIGHTS = {
    "failed_login_count":     lambda n: min(n * 2, 30),
    "known_attacker_ip":      25,
    "high_abuseipdb_score":   20,
    "multiple_usernames":     10,
    "port_scan_detected":     15,
    "sql_injection_pattern":  20,
    "after_hours_activity":   5,
    "foreign_country":        5,
    "repeated_403_errors":    8,
    "otx_pulse_match":        15,
}
```

**Dashboard Pages:**
1. Live Overview (auto-refresh 30s, attack timeline, top attackers)
2. Threat Hunting (filters, log table, CSV export)
3. IP Intelligence (full profile, AbuseIPDB, OTX, world map)
4. Incidents (grouped attack campaigns, attack chain)
5. AI Analyst (LangChain report generation, streaming output)

**MongoDB Collections:** logs, threat_actors, incidents, reports

**API Endpoints:**
```
POST   /api/v1/logs/upload
POST   /api/v1/logs/ingest
GET    /api/v1/logs
GET    /api/v1/analysis/summary
GET    /api/v1/analysis/top-attackers
GET    /api/v1/analysis/timeline
POST   /api/v1/analysis/ip/{ip}
GET    /api/v1/incidents
POST   /api/v1/reports/generate
```

**How to Run:**
```bash
cd backend && uvicorn main:app --reload --port 8000
streamlit run dashboard/app.py
```

---

### 🍯 Project 3 — HoneyShield Intelligence Platform (Honeypot)

**What:** Cybersecurity deception platform using Python raw sockets to 
simulate vulnerable services — attracts, captures, and analyzes real 
attacker behavior.

**Status:** Prompt complete. Ready to build.

**Tech Stack:**
```
Language:    Python (everything)
Networking:  Raw Python socket programming (NO libraries)
Database:    SQLite (raw sqlite3, NO ORM)
Dashboard:   Streamlit (multi-page, 6 pages)
Charts:      Plotly
Data:        Pandas
HTTP:        Requests + Aiohttp
AI:          OpenAI + LangChain
```

**Important:** No Docker. No ORMs. Everything manual. This is a learning project.

**Honeypot Services:**
```
Fake SSH     → port 2222  (banner: SSH-2.0-OpenSSH_8.9p1 Ubuntu)
Fake FTP     → port 2121  (banner: 220 ProFTPD 1.3.5e Server)
Fake HTTP    → port 8080  (fake WordPress wp-admin login page)
Fake Telnet  → port 2323  (Ubuntu 20.04 LTS login prompt)
```

**Core Features:**
- Raw TCP socket servers (one thread per connection)
- Credential capture (every username + password logged)
- Brute force detection (10+ attempts in 5 min → CRITICAL alert)
- Credential stuffing detection (5+ usernames from same IP)
- Rapid-fire detection (<1 second between attempts → automated tool)
- Multi-service detection (same IP hits 2+ services)
- IP geolocation (ip-api.com — free, no key)
- AbuseIPDB reputation check
- AlienVault OTX pulse lookup
- Threat scoring engine (weighted 0–100)
- IOC file matching (known_bad_ips.txt)
- Alert engine with evidence + recommendations
- Correlation engine (campaign detection by ASN + time window)
- AI security analyst (OpenAI + LangChain)

**Threat Score Weights:**
```python
THREAT_WEIGHTS = {
    "connections_over_20":         20,
    "login_attempts_over_50":      30,
    "multiple_usernames_over_5":   10,
    "rapid_fire_under_1_second":   15,
    "multi_service_targeting":     15,
    "known_bad_ip":                30,
    "abuseipdb_score_over_80":     20,
    "otx_pulse_match":             15,
    "tor_exit_node":               15,
}
VERDICTS = { (0,15):"LOW", (15,35):"MEDIUM", (35,60):"HIGH", (60,101):"CRITICAL" }
```

**SQLite Tables:**
attackers, connections, login_attempts, attacker_commands, 
alerts, ai_reports, service_stats, ioc_matches

**Dashboard Pages:**
1. Live Feed (auto-refresh 15s, real-time connection stream)
2. Attacker Intelligence (IP profiles, leaderboard, AbuseIPDB gauge)
3. Analytics (timeline, top attackers, world map, heatmap)
4. Alerts (CRITICAL/HIGH/MEDIUM/LOW cards, acknowledge, investigate)
5. Threat Hunting (IOC search, campaign detection, pattern queries)
6. AI Analyst (LangChain threat reports, streaming chat UI)

**Build Phases:**
1. Raw sockets + SQLite + SSH honeypot → test with `nc localhost 2222`
2. FTP/Telnet/HTTP + credential logging + brute force alerts
3. Geo + AbuseIPDB + OTX + threat scoring
4. Streamlit dashboard (all 6 pages)
5. Correlation engine + threat hunting
6. AI analyst (OpenAI + LangChain)

**How to Run:**
```bash
python -c "from database.db import init_db; init_db()"
python main.py
streamlit run dashboard/app.py
nc localhost 2222   # test connection
```

---

### 🎯 Project 4 — ThreatHunter Intelligence Platform (Main Project)

**What:** Production-grade threat intelligence and IOC investigation 
platform for SOC analysts. Investigates IPs, domains, hashes, URLs 
using live APIs. Full case management, CVE tracking, AI analyst.

**Status:** Core platform built. Auth + RBAC + Admin panel being added.

**Tech Stack:**
```
Frontend:  React 18 + Vite + Tailwind + shadcn/ui + Recharts
Backend:   Node.js + Express.js
Database:  Supabase (PostgreSQL + Auth)
HTTP:      Axios + TanStack React Query
Security:  Helmet, express-rate-limit, express-validator
Logging:   Winston
```

**Live API Integrations:**
```
AbuseIPDB   → IP reputation + abuse score (1000/day free)
OTX         → Threat pulses + IOC correlation
IPInfo      → Country, city, ISP, ASN (50k/month free)
NIST NVD    → Live CVE feed (free, no key needed)
VirusTotal  → Hash/domain/URL analysis (500/day free)
```

**IMPORTANT:** All external API calls go through the backend ONLY.
Never call threat intel APIs directly from React frontend.

**Design System:**
```css
--bg-primary:   #030712
--bg-secondary: #0f172a
--bg-tertiary:  #1e293b
--accent-cyan:  #06b6d4
--accent-green: #10b981
--accent-amber: #f59e0b
--accent-red:   #ef4444
--font-mono:    JetBrains Mono
--font-sans:    Inter
```

**Frontend Pages:**
Dashboard, IOC Investigator, CVE Intelligence, 
Threat Hunting Workspace, Analytics, Reports, Settings, Admin Panel

**Backend API Endpoints:**
```
POST   /api/ioc/investigate       ← master IOC lookup endpoint
GET    /api/ip/:address
GET    /api/domain/:domain
GET    /api/hash/:hash
GET    /api/cve/feed
GET    /api/cve/:cveId
GET    /api/cve/search
GET    /api/investigations
POST   /api/investigations
GET    /api/investigations/:id
PUT    /api/investigations/:id
POST   /api/investigations/:id/indicators
POST   /api/investigations/:id/notes
POST   /api/reports/generate
GET    /api/stats/dashboard
GET    /api/admin/users
POST   /api/admin/users/invite
PUT    /api/admin/users/:id
POST   /api/admin/users/:id/suspend
GET    /api/admin/audit
GET    /api/setup/guide
GET    /api/setup/validate
GET    /api/health
```

**Supabase Tables:**
investigations, indicators, cves, notes, investigation_indicators, 
reports, api_cache, api_health, user_profiles, roles, user_roles, 
token_blacklist, audit_logs, user_sessions, invitations

**Roles:**
```
admin   → Full access: user management, API keys, audit logs, all data
analyst → Threat hunting: investigations, IOC search, reports (own only)
viewer  → Read-only: view investigations, search IOCs, view reports
```

**Permission System:**
```javascript
PERMISSIONS = {
  'users:read', 'users:write', 'users:delete', 'roles:manage',
  'investigations:read', 'investigations:write', 'investigations:all',
  'indicators:read', 'indicators:write', 'indicators:all',
  'reports:read', 'reports:write', 'reports:all',
  'settings:write', 'api_keys:manage', 'audit:read', 'system:config',
  'dashboard:admin', 'dashboard:analyst', 'dashboard:viewer',
  'ioc:search', 'cve:read'
}
```

**Security Stack:**
- Helmet with full CSP + HSTS headers
- Rate limiting: auth 10/15min, IOC 30/min, global 100/15min
- JWT 8-hour expiry with silent rotation after 4 hours
- Token blacklist table for secure logout
- Full audit_logs — every action logged with IP + user agent
- Input validation before ANY external API call
- RLS policies on all Supabase tables
- Private IPs blocked from IOC investigation
- API keys stored encrypted, never returned in full

**Production Hardening (Latest Work):**

1. **Startup Diagnostics** — checks DB connection, all tables exist, 
   RLS enabled, all API keys valid, prints status table on boot

2. **API Key Validator** — tests each key against real endpoint, 
   shows exact signup URL + step-by-step instructions for missing keys,
   Setup Wizard page for new installations

3. **Auth System** — Supabase Auth, email verification required,
   password strength validation, lockout after 10 failed attempts,
   session listing, individual session revocation, MFA (TOTP)

4. **User Management** — invite by email, suspend/activate,
   force logout all sessions, password reset, activity stats per user

5. **Admin Panel (7 pages):**
   - Admin Dashboard (system stats, recent activity, API health)
   - All Users (table with full management actions)
   - Invite User (email invitation with role assignment)
   - Roles & Permissions (permission toggles per role)
   - Audit Logs (full filterable log, CSV export)
   - API Keys (test + update each key, usage stats)
   - Active Sessions (all sessions across all users, force revoke)

**Caching Strategy:**
```
IP/domain lookups:  1 hour TTL
OTX pulse data:     6 hours TTL
CVE data:           6 hours TTL
Geo data:           24 hours TTL
Auth responses:     NEVER cached
```

**Response Format (all endpoints):**
```json
{
  "success": true,
  "data": {},
  "error": null,
  "meta": {
    "source": "live | cache | stale_cache",
    "cached_at": "ISO 8601",
    "expires_at": "ISO 8601",
    "is_fresh": true
  },
  "timestamp": "ISO 8601"
}
```

**How to Run:**
```bash
# Backend
cd backend && npm install && node server.js
# → http://localhost:3001

# Frontend  
cd frontend && npm install && npm run dev
# → http://localhost:5173

# Supabase schema
# Run supabase/schema.sql in Supabase SQL editor
```

---

## 🔮 Future Projects (Template for New Ones)

When I start a **new project**, assume this stack unless I say otherwise:

**If cybersecurity + Python:**
```
Backend:   Python + FastAPI
Database:  MongoDB (Motor) for logs / PostgreSQL (SQLAlchemy) for structured
Dashboard: Streamlit OR React frontend
Charts:    Plotly (Streamlit) / Recharts (React)
AI:        OpenAI + LangChain
APIs:      AbuseIPDB, OTX, IPInfo as needed
```

**If cybersecurity + full-stack web:**
```
Frontend:  React 18 + Vite + Tailwind + shadcn/ui
Backend:   Node.js + Express OR Python + FastAPI
Database:  Supabase (if auth needed) / MongoDB / PostgreSQL
Auth:      Supabase Auth + RBAC (if user management needed)
Security:  Helmet + rate limiting + input validation + audit logs
```

**Always include for any new project:**
- Dark cybersecurity design system (colors above)
- JetBrains Mono for all technical data display
- Phase-by-phase build order with tests
- Real live data only (no mock/dummy)
- .env template with all variables
- Complete folder structure
- All database schemas
- All API endpoint definitions

---

## 📋 What I Need From You Every Session

| When I say | What you do |
|------------|-------------|
| "generate a prompt" | Complete paste-ready prompt for Claude Code with folder structure, schemas, endpoints, phases, test commands |
| "make this better" | Improve the prompt/code significantly, add what's missing |
| "something is broken" | Debug step by step, identify root cause, give exact fix |
| "continue" | Ask me which project and what phase, then continue from there |
| "start fresh" | New project — ask me what it is, then generate full prompt |
| "what stack should I use" | Recommend based on project type using my established stacks |
| "explain this" | Simple clear explanation, code example if helpful |
| "is this good" | Honest assessment, tell me what's wrong, what's missing |

---

## 🚫 Rules — Never Do These

- Never suggest Docker or Kubernetes
- Never use mock data, fake JSON, or dummy datasets
- Never hardcode API keys anywhere
- Never build everything at once — always phases
- Never skip the test step between phases
- Never expose API keys to the frontend
- Never use placeholder/lorem ipsum data in real projects
- Never assume I want a basic tutorial — I am building real tools

---

## ✅ Rules — Always Do These

- Real live data from real APIs always
- Phase by phase with a test after each phase
- Complete .env.example template in every project
- Security first — validate inputs, rate limit, audit log
- JetBrains Mono for all hashes, IPs, CVE IDs, domains
- Dark cybersecurity theme on every project
- Practical responses — give code and commands, not essays
- If something will break later, warn me now
- Tell me the exact command to run to test each thing

---

*Last updated: Session with original Claude account — all 4 projects complete*
*Save this file as CLAUDE_CONTEXT.md and paste it at the start of every new session*

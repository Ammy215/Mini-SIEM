# 🛡️ Mini SIEM

A Security Information & Event Management system built from scratch. It takes
in logs from servers, web servers, firewalls and Windows hosts; turns them into
one common event shape; stores them in PostgreSQL; runs detection rules over
them continuously; and raises alerts tagged with the MITRE ATT&CK technique
they match — then groups an attacker's alerts into a single incident.

It is deliberately small enough to understand end to end, and shaped like the
real thing (Splunk, Elastic Security, Microsoft Sentinel) where it counts.

```
Log sources ─► Collector ─► Parse + normalise ─► PostgreSQL ─► Detection engine ─► Alerts ─► Incidents
 (upload, API,             (11 formats,          (one events    (15 rules, threshold     (score,    (correlated
  live syslog)              auto-detected)        table)         / signature / sequence)  enrichment) per attacker)
```

## What it detects

| Rule | Type | MITRE ATT&CK | Minimum severity |
|---|---|---|---|
| Brute force login attempts | threshold | T1110 | high |
| Password spray | threshold | T1110.003 | high |
| Credential stuffing | threshold | T1110.004 | high |
| Successful login after brute force | sequence | T1110 | critical |
| Port scan | threshold | T1046 | medium |
| Port scan blocked by the firewall | threshold | T1046 | medium |
| Host sweep seen by the firewall | threshold | T1046 | medium |
| SQL injection in an HTTP request | signature | T1190 | high |
| Cross-site scripting in an HTTP request | signature | T1059.007 | medium |
| Path traversal in an HTTP request | signature | T1083 | high |
| Known scanner tool user agent | signature | T1595 | medium |
| Windows event log cleared | signature | T1070.001 | high |
| Account added to a privileged Windows group | signature | T1098 | high |
| Windows account created | signature | T1136 | medium |
| Privileged logon by a user account | signature | T1078 | low |

Rules are written in a validated rule language (match, aggregate over a
sliding window, or a two-step sequence), stored in the database, and editable
in the app — admins can build and dry-run their own rules before saving them.

**It is rule-based by design.** An attack no rule describes produces events but
no alert. Every event is kept and searchable, so what detection missed at the
time can still be found afterwards — but "nothing alerted" never means "nothing
happened". Anomaly / ML detection is out of scope on purpose.

## Features

- **Ingestion** — file upload with format auto-detection, a JSON ingest API, and
  an optional local syslog listener (UDP/TCP). Formats: OpenSSH auth logs,
  Nginx/Apache combined, Windows Event Logs (XML and PowerShell JSON), CEF (Palo
  Alto, Fortinet, Check Point), iptables/nftables/UFW, syslog RFC 3164 and 5424,
  JSON, CSV, key=value — and a fallback that stores anything else rather than
  dropping it. Hostile XML (entities, external references) is refused.
- **Historical analysis** — an uploaded log is analysed over its *own* dates, so
  an attack in a months-old file is still found.
- **Scoring** — each alert gets a 0–100 threat score from its rule and from
  context: AbuseIPDB reputation, AlienVault OTX pulses, a foreign source
  country, activity outside business hours. A provider that is down costs only
  its own signals, and is retried.
- **Correlation** — alerts from one source within an hour become one incident,
  with a timeline of how it unfolded.
- **Investigation** — every alert shows its evidence: the score breakdown, what
  triggered it, what each threat-intel provider returned, and which signals were
  considered but not counted. An optional AI summary (Groq) explains it in plain
  English.
- **Dashboard** — events and alerts over a chosen time range, login and source
  breakdowns, a world map of attack origins, and a MITRE ATT&CK coverage matrix.
- **Access control** — its own JWT auth (short access token, httpOnly refresh
  cookie), bcrypt, account lockout, and three roles (viewer, analyst, admin).
  Every sensitive action is written to an audit log with IP and user agent.

## Tech stack

| | |
|---|---|
| Backend | Python 3.13, FastAPI, Uvicorn, Pydantic v2, asyncpg (parameterised SQL, no ORM) |
| Database | PostgreSQL (Neon), versioned forward-only migrations |
| Frontend | React 18, Vite, Tailwind, shadcn/ui, Recharts, Framer Motion, TanStack Query |
| Threat intel | AbuseIPDB, AlienVault OTX, IPInfo — called from the backend only |
| Deploy | Vercel (frontend) proxying `/api` to Render (backend) |
| CI | GitHub Actions — lint, dependency audit, full test suite, build |

The frontend reaches the API through its own origin (`/api`, proxied), so the
refresh cookie is first-party and no API key or database address ever reaches
the browser.

## Run locally (Windows)

```bash
# backend
cd backend
python -m venv venv && venv\Scripts\activate
pip install -r requirements-dev.txt     # production installs requirements.txt only
copy .env.example .env                  # then fill it in
python scripts/migrate.py
python scripts/seed_rules.py
python scripts/seed_admin.py
uvicorn main:app --reload --port 8000   # API docs: http://localhost:8000/docs

# frontend (new terminal)
cd frontend
npm install
copy .env.example .env                  # leave VITE_API_BASE_URL empty: /api is proxied
npm run dev                             # http://localhost:5173
```

Sign in with the `ADMIN_EMAIL` / `ADMIN_PASSWORD` from `backend/.env`.

## Testing

```bash
cd backend  && python -m pytest tests      # unit + integration, against a real PostgreSQL
cd backend  && ruff check . && pip-audit -r requirements.txt
cd frontend && npm run lint && npm run build
cd frontend && npm run e2e                  # Playwright smoke test against the running app
```

The test catalogue for manual and adversarial checks is in
[`TESTING_GUIDE.md`](./TESTING_GUIDE.md); known limitations and deliberately
deferred work are in [`FUTURE_UPGRADES.md`](./FUTURE_UPGRADES.md).

## Security notes

- Production refuses to start with the example `SECRET_KEY`, with a key shorter
  than 32 bytes, or while an admin account still has the example password.
- Detection rules compile to parameterised SQL over a whitelist of fields;
  user-written regular expressions run only inside PostgreSQL, under a timeout.
- The Attack Lab (deliberately vulnerable practice endpoints for testing
  detection with Burp Suite) exists only when `ENABLE_ATTACK_LAB=true` and must
  stay off in production.

## License

MIT — see [LICENSE](./LICENSE).

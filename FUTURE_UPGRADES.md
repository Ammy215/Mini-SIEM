# 🔮 Future Upgrades / Known Limitations

Deliberate v2 ideas and accepted limitations of the current build.

> **Hard rule: nothing in this file is in scope.** Do not implement any part of
> it unless asked directly in a future session. It exists so these decisions are
> recorded as *considered and deferred*, not overlooked.

---

## 1. Multi-tenancy

**Current state — single-tenant.** Mini SIEM has one shared pool of users and
roles (`viewer` / `analyst` / `admin`) that apply globally across the whole app.
There is no concept of separate organizations: an `analyst` is an analyst over
*all* data, and an `admin` administers *everything*. Every row in `events`,
`alerts`, `incidents` and `rules` belongs to the one and only tenant.

**A v2 could add real multi-tenancy:** multiple organizations, each with its own
admin/analyst/viewer scoped **only** to that org's own data.

### What that would actually require

- A new `organizations` table.
- An `organization_id` column added to every data table — `events`, `alerts`,
  `incidents`, `rules`, `users`.
- **Every existing query in the app updated to filter by the current user's
  `organization_id`.** This is the highest-risk part of the whole change: a
  single missed filter anywhere would let one org read another org's data. It
  touches every router (`events`, `alerts`, `incidents`, `rules`, `stats`,
  `admin`) *and* the detection engine, which currently aggregates across the
  entire `events` table with no tenant predicate (`detection/threshold.py`,
  `detection/signature.py`, `detection/correlate.py`).
- Registration flow updated to support "create a new org" vs. "join an existing
  org".
- Each org's first user becomes that org's own admin, independent of every other
  org's admin.

### Why it's deferred

The blast radius is the entire data layer, and the failure mode (cross-tenant
data leakage in a *security* product) is the worst kind of bug this project
could ship. It is not worth doing incrementally or halfway. If ever built, it
should be its own dedicated, fully-tested phase — with a test that explicitly
asserts org A cannot read org B's rows through **every** read endpoint.

---

## 2. Investigation ownership / visibility scoping

**Current state — everything is globally visible.** Once a user is approved,
their role controls what they can *do* (`viewer` read-only, `analyst` can act,
`admin` manages users/rules), but not what they can *see*. Every event, alert,
and incident is visible to every approved user regardless of role — there is no
concept of a private workspace, a case assigned to one analyst, or anything
hidden from a `viewer` mid-investigation.

**A v2 could add ownership / visibility scoping:** an optional `assigned_to`
(user id) and/or `is_private` flag on `alerts` and `incidents`, so an admin or
analyst can work a sensitive case without every other approved user — including
every `viewer` — watching it unfold in real time.

### What that would actually require

- `assigned_to UUID REFERENCES users(id)` and `is_private BOOLEAN` columns on
  `alerts` and `incidents`.
- Read endpoints (`GET /api/alerts`, `GET /api/alerts/{id}`, `GET /api/incidents`,
  `GET /api/incidents/{id}`, and the dashboard/stats aggregates that roll them up)
  updated to hide a private row from anyone who isn't its assignee or an admin.
- An explicit assign/claim action (e.g. `PUT /api/alerts/{id}` gains an
  `assigned_to` field) plus an audit entry for both assignment and any visibility
  change — hiding data from other analysts is itself a sensitive action worth a
  trail.
- Frontend: an "assigned to me" filter and a visual indicator for private/claimed
  items on the Alerts and Incidents pages.

### Why it's deferred

**This is distinct from [multi-tenancy](#1-multi-tenancy).** Multi-tenancy
isolates entire separate organizations from each other — different companies
that must never see one another's data at all. This is about visibility *within*
one shared team: everyone is still on the same tenant, same rule set, same
detection engine; only who currently sees a specific in-progress row differs.
The two could coexist (each org could later add ownership scoping inside itself)
but neither implies the other, and this one is far smaller — it touches the read
paths of two tables, not the entire data layer.

Deferred for v1 because nothing so far has needed it: with one shared analyst
team, full visibility has been a feature (anyone can pick up any alert), not a
gap. It becomes worth building the moment there's a real need to keep an
in-progress investigation — e.g. one involving an insider — from being visible
to the whole team before it's confirmed.

---

## 3. Session / token revocation

**Current state — stateless JWTs, no revocation.** Resetting a user's password
or suspending their account does **not** invalidate JWTs that have already been
issued. They remain valid until natural expiry:

| Token | TTL | Setting |
|---|---|---|
| Access | ~30 min | `JWT_ACCESS_TTL_MIN` |
| Refresh | 7 days | `JWT_REFRESH_TTL_DAYS` |

This is a direct consequence of the design: `auth/deps.py::get_current_user`
only decodes and verifies the token signature — it never re-checks the database
— so a valid signature is accepted until the `exp` claim passes.

### The v2 fix

- Add a `token_version` integer column to `users`.
- Embed it in the JWT payload at login (`auth/jwt.py::create_access_token`).
- Check it matches the user's current value on every decode.
- Increment it on password reset or suspension — which immediately invalidates
  **all** of that user's existing tokens, access and refresh alike.

Note this trades away part of what makes stateless JWTs attractive: every
request would need a `token_version` lookup, so it should land alongside a
short-TTL/caching strategy rather than a naive per-request query.

### Interim mitigation (works today)

For a genuinely compromised account, the effective sequence is:

```
suspend  ->  reset password  ->  reactivate
```

Suspending sets `is_active = FALSE`, and `POST /api/auth/refresh` **does**
re-check `is_active` against the database — so suspension immediately kills the
attacker's ability to mint new access tokens. Their existing access token still
works until it expires (≤30 min), but it cannot be renewed.

---

## 4. Smaller known limitations

Each of these is understood, accepted for v1, and small enough to fix on its own.
Roughly ordered by how much they'd matter on a public deployment.

### 4.1 Rate limiter is in-memory (single-process, resets on restart)

`auth/rate_limit.py` and `middleware/global_rate_limit.py` keep their sliding
windows in a process-local dict. Consequences:

- Every restart clears all buckets. On Render's free tier — where the service
  sleeps when idle and cold-starts on the next request — an attacker could
  reset their own limit just by pausing.
- It only works correctly with **one** backend process. Scaling to multiple
  instances or workers would give each its own independent counter, multiplying
  the effective limit by the instance count.

Deliberate for v1 (the stack is locked to "no Redis"). The fix, if the app ever
scales out, is a shared store — Redis, or a Postgres table with a TTL sweep.

### 4.2 User enumeration via registration

`POST /api/auth/register` returns `409 Email already registered` for a duplicate
address, which lets anyone test whether a given email has an account. Login
itself is already safe (a generic 401 plus `verify_dummy()` for timing parity in
`auth/password.py`) — registration is the remaining leak.

The fix is to return the same generic accepted-response either way, which costs
legitimate users a clear "you already have an account" message. Worth doing
alongside a real signup/approval UX rather than in isolation.

### 4.3 No password-reset UI

Admin-driven reset works (`PUT /api/admin/users/{id}` with `password`) but is
API-only — the Admin page has no control for it, so it currently requires curl
or `/docs`. There is still no self-service "forgot password" flow at all, which
would need an email provider and is a much bigger piece of work.

### 4.4 No user-deletion endpoint

There is no `DELETE /api/admin/users/{id}`. Admins can suspend
(`is_active = FALSE`) but not remove. Actual deletion currently requires direct
SQL, and has to clear `audit_log.user_id` first because of the foreign key —
which is arguably the real design question: deleting a user destroys their audit
trail. A proper fix is probably soft-delete, or `ON DELETE SET NULL` on
`audit_log.user_id` to preserve history.

### 4.5 `react-router-dom` v6 has open moderate advisories

`npm audit` reports two moderate issues (open redirect via backslash in `<Link>`
/ `useNavigate`, and constructor injection via `deserializeErrors()` in SSR
hydration). The only fix `npm` offers is `react-router-dom@7`, a breaking major
upgrade. The SSR advisory doesn't apply — this is a pure client-side SPA with no
server-side rendering. Deferred as a scheduled dependency upgrade rather than a
rushed pre-deploy change.

### 4.6 Frontend ships as one 898 KB bundle

`npm run build` emits a single ~898 KB JS chunk (~269 KB gzipped) and Vite warns
about it. Fine functionally, but it means the whole app — Recharts included —
downloads before the login screen renders. The fix is route-level `React.lazy()`
code splitting, or `manualChunks` to separate the charting library.

### 4.7 ~~SSH parser assumes the current year~~ — fixed in Phase 13

`parsers/timeutil.py::parse_yearless` now picks the most recent year in which
the date exists and isn't more than a day in the future: a `Dec 31` line read
on Jan 1 lands in last year, `Feb 29` lands in the latest leap year, and an
impossible date (`Feb 30`) skips that line instead of failing the upload with a
500. The Python 3.15 `strptime` deprecation is gone too.

What remains: a year-less log **more than a year old** still gets a recent
year, because the line itself carries no way to tell. A per-upload year hint
closes that (planned with the upload UI).

### 4.8 ~~Unicode bidi overrides can spoof text in the UI~~ — fixed in Phase 18

**Fixed:** log-derived text now renders through `frontend/src/components/LogText.jsx`,
which shows each bidi control character (U+202A–U+202E, U+2066–U+2069) as a
visible `[U+202E]` marker, highlighted with an explanatory tooltip, instead of
letting it reorder the text. It is used on Events, Alerts, Incidents, the
Dashboard's recent alerts and live feed, and the Upload page. The stored value
is unchanged. The original finding is kept below for the record.

Log content is stored verbatim and rendered by React as escaped text, which is
correct and safe — no XSS. But *escaped* is not the same as *unambiguous*: a
value containing a bidirectional control character such as U+202E
(RIGHT-TO-LEFT OVERRIDE) renders with the following characters reversed.

Verified during adversarial testing: a username stored as `ADVTEST\u202Egnp.exe`
displays in the Events table as **`ADVTESTexe.png`** — the classic filename
spoofing trick. The stored value is intact and a database query shows the truth;
only the rendered view misleads.

Low severity — no code executes and nothing is corrupted — but it matters more
than usual in a tool whose entire job is showing an analyst what happened. An
attacker who can get a string into a log field can make it *read* as something
else in the console.

Fix would be display-layer: strip or visibly escape the Unicode bidi control
range (U+202A–U+202E, U+2066–U+2069) when rendering log-derived values, ideally
in one shared cell component rather than per page.

### 4.9 AI summaries: prompt injection is mitigated, not eliminated

The opt-in "Summarize with AI" button sends an alert's or incident's evidence to
Groq. Some of that evidence — URLs, user agents, matched text — is written by the
attacker, which makes it a prompt-injection channel. Current mitigations:

- Only an allow-list of fields is sent (`ai/summarize.py::build_alert_payload`);
  never the raw evidence blob, usernames, event ids, or the IP lists stored with
  threshold alerts.
- Evidence is fenced between markers the attacker cannot close (`<<<`/`>>>` in
  the data are neutralised), and the system prompt says the fenced content is data,
  never instructions.
- The response is rendered as plain text, so a hostile completion cannot inject
  markup into the page.
- Every request is written to `audit_log` *before* the call, since that is the
  moment evidence leaves the server; the summary text itself is not stored.

What remains: a sufficiently crafted payload can still skew the model's wording
or assessment — no prompt defence is complete. Summaries are labelled
AI-generated and must be checked against the evidence shown beside them; they are
never used to change severity, status, or any detection outcome.

### 4.10 shadcn components were generated for Tailwind 4; the project runs Tailwind 3

`frontend/components.json` uses the `radix-nova` style, whose components are
written in Tailwind 4 syntax (`px-(--card-spacing)`, `in-data-[…]:`,
`rounded-4xl`). Under Tailwind 3.4 those classes compile to nothing, silently.
Every Card lost its inner padding this way, on every page, until Phase 18
rewrote `card.jsx` and `badge.jsx` in Tailwind 3 classes.

Still written in Tailwind 4 syntax but harmless today: `select.jsx` (imported by
no page — the app uses native `<select>`) and the button-group / icon-slot
variants in `button.jsx` (no button groups exist). Any shadcn component added
later needs the same check, or the project should move to Tailwind 4 as a
deliberate upgrade.

### 4.11 The live syslog listener trusts the network it runs on

Syslog (RFC 3164/5424) has no authentication, and a UDP packet's source address
can be forged. The listener added in Phase 26 limits the damage — it's off by
default, binds loopback unless told otherwise, refuses to listen on every
interface in production, accepts only `SYSLOG_ALLOWED_SOURCES`, and rate-limits
and size-caps each sender — but anyone who can put packets on an allowed
network can still inject fake events, and so fake or hide alerts.

That makes it a local-lab feature, not an internet-facing one. The real fix is
syslog over TLS with client certificates (RFC 5425) or an agent that
authenticates to the ingest API; both are deferred. A hosted deployment on
Render's free tier can't receive syslog at all, so production keeps
`ENABLE_SYSLOG_LISTENER` unset.

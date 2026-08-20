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

## 2. Session / token revocation

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

## 3. Smaller known limitations

Each of these is understood, accepted for v1, and small enough to fix on its own.
Roughly ordered by how much they'd matter on a public deployment.

### 3.1 Rate limiter is in-memory (single-process, resets on restart)

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

### 3.2 User enumeration via registration

`POST /api/auth/register` returns `409 Email already registered` for a duplicate
address, which lets anyone test whether a given email has an account. Login
itself is already safe (a generic 401 plus `verify_dummy()` for timing parity in
`auth/password.py`) — registration is the remaining leak.

The fix is to return the same generic accepted-response either way, which costs
legitimate users a clear "you already have an account" message. Worth doing
alongside a real signup/approval UX rather than in isolation.

### 3.3 No password-reset UI

Admin-driven reset works (`PUT /api/admin/users/{id}` with `password`) but is
API-only — the Admin page has no control for it, so it currently requires curl
or `/docs`. There is still no self-service "forgot password" flow at all, which
would need an email provider and is a much bigger piece of work.

### 3.4 No user-deletion endpoint

There is no `DELETE /api/admin/users/{id}`. Admins can suspend
(`is_active = FALSE`) but not remove. Actual deletion currently requires direct
SQL, and has to clear `audit_log.user_id` first because of the foreign key —
which is arguably the real design question: deleting a user destroys their audit
trail. A proper fix is probably soft-delete, or `ON DELETE SET NULL` on
`audit_log.user_id` to preserve history.

### 3.5 `react-router-dom` v6 has open moderate advisories

`npm audit` reports two moderate issues (open redirect via backslash in `<Link>`
/ `useNavigate`, and constructor injection via `deserializeErrors()` in SSR
hydration). The only fix `npm` offers is `react-router-dom@7`, a breaking major
upgrade. The SSR advisory doesn't apply — this is a pure client-side SPA with no
server-side rendering. Deferred as a scheduled dependency upgrade rather than a
rushed pre-deploy change.

### 3.6 Frontend ships as one 898 KB bundle

`npm run build` emits a single ~898 KB JS chunk (~269 KB gzipped) and Vite warns
about it. Fine functionally, but it means the whole app — Recharts included —
downloads before the login screen renders. The fix is route-level `React.lazy()`
code splitting, or `manualChunks` to separate the charting library.

### 3.7 SSH parser assumes the current year

`parsers/ssh.py` parses syslog-style timestamps (`Jan 10 10:00:01`) that carry no
year, and fills in the current one. Two consequences: logs that span a New Year
boundary get mis-dated, and Python 3.15 will change `strptime`'s behaviour here
(it already emits a `DeprecationWarning`, visible in every test run). The fix is
to pass an explicit year rather than relying on the default.

### 3.8 Unicode bidi overrides can spoof text in the UI

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

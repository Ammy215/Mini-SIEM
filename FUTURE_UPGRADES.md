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

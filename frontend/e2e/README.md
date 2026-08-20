# End-to-end smoke test

`smoke.js` walks the whole app in a real browser: login, every core page,
the Attack Lab (login + search forms, run detection), and a mobile
responsive check. It's the automated stand-in for the manual Playwright
verification done throughout Phases 8-10.

This is **not** run in CI — it needs the backend, the frontend dev server,
and a seeded database all running locally at once, which is a heavier setup
than CI needs for the automated (unit + integration) suite. Run it yourself
after a change you want to sanity-check end-to-end.

## Run it

1. Backend running at `http://localhost:8000` (`uvicorn main:app --reload`),
   with `ENABLE_ATTACK_LAB=true` in `backend/.env` if you want the Attack Lab
   section to run (it's skipped, not failed, if the flag is off).
2. Frontend dev server running at `http://localhost:5173` (`npm run dev`).
3. `npm run e2e`

Override the target URL or credentials with `E2E_FRONTEND_URL`,
`E2E_ADMIN_EMAIL`, `E2E_ADMIN_PASSWORD` env vars if yours differ from the
`.env.example` defaults.

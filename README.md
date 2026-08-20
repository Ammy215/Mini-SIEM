# 🛡️ Mini SIEM

A small, from-scratch Security Information & Event Management system. It
collects logs, normalizes them into one schema, stores them in PostgreSQL,
runs a detection engine (threshold + signature rules) tagged with MITRE
ATT&CK technique IDs, and surfaces alerts/incidents on a dashboard.

Full spec: [`CLAUDE.md`](./CLAUDE.md).

## Pipeline

```
Log sources → Collector → Parse/normalize → PostgreSQL → Detection engine → Alerts + dashboard
```

## Tech stack

- **Backend:** Python, FastAPI, Uvicorn, Pydantic v2, PostgreSQL
- **Auth:** own JWT (access + refresh) + bcrypt + RBAC
- **Frontend:** React 18, Vite, Tailwind, shadcn/ui, Recharts, Framer Motion
- **Deploy:** Vercel (frontend), Render (backend + Postgres)
- **CI:** GitHub Actions

## Status

Build is happening in numbered phases (see `CLAUDE.md`). Currently: **Phase 0
— repo hygiene.**

## Run locally (Windows)

```bash
# backend
cd backend
python -m venv venv && venv\Scripts\activate
pip install -r requirements.txt
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

## License

MIT — see [LICENSE](./LICENSE).

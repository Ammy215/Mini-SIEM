# Mini SIEM Tool
Self-hosted, single-tenant SIEM: ingests logs, normalizes them into one event schema, runs
rule- and IOC-based detection, and surfaces alerts on a live dashboard.

Full spec: [mini-siem-master-guide.md](./mini-siem-master-guide.md).
Working conventions: [CLAUDE.md](./CLAUDE.md).

## Local setup

```
cp .env.example .env
docker compose up
```

- Backend: http://localhost:8000/health
- Frontend: http://localhost:3000

*README will get the full README-structure treatment (Part 7 of the master guide — GIF, architecture
diagram, attack-and-detect worked example) once there's something to show.*

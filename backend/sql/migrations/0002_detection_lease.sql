-- One row a detection run claims before it starts, so the 60-second scheduler
-- and a manual POST /api/detect/run can't overlap and insert the same alerts
-- twice.
--
-- A lease row rather than a Postgres advisory lock: the app connects through
-- Neon's PgBouncer in transaction mode, which can run a session lock and its
-- unlock on different server connections. Claiming the lease is one atomic
-- UPDATE, which behaves the same through any pooler, and a lease left behind
-- by a crashed process simply expires.
CREATE TABLE IF NOT EXISTS detection_lease (
  id          INT PRIMARY KEY CHECK (id = 1),
  holder      UUID,
  acquired_at TIMESTAMPTZ,
  expires_at  TIMESTAMPTZ
);

INSERT INTO detection_lease (id) VALUES (1) ON CONFLICT DO NOTHING;

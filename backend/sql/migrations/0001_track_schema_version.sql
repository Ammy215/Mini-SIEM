-- First versioned migration. The schema_migrations table itself is created by
-- the runner (migrations.py) before any migration runs, so this one only
-- documents it; real schema changes start at 0002.
COMMENT ON TABLE schema_migrations IS
  'Applied migrations from backend/sql/migrations. Managed by scripts/migrate.py; never edit by hand.';

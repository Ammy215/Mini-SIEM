-- How each rule's most recent detection run went. A rule that fails (a
-- statement timeout, a regex PostgreSQL rejects) used to fail silently in the
-- server log; this lets the Rules page show it.
CREATE TABLE IF NOT EXISTS rule_state (
  rule_id            INT PRIMARY KEY REFERENCES rules(id) ON DELETE CASCADE,
  last_run_at        TIMESTAMPTZ,
  last_duration_ms   INT,
  last_alerts        INT,
  last_error         TEXT,
  last_error_at      TIMESTAMPTZ,
  consecutive_errors INT NOT NULL DEFAULT 0
);

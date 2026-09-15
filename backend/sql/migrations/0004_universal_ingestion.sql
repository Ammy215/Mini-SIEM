-- Universal ingestion: every upload becomes a recorded batch, and events gain
-- the fields that Windows, firewall and generic key=value/CSV/JSON logs carry.

CREATE TABLE IF NOT EXISTS ingest_batches (
  id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  filename           TEXT NOT NULL,
  sha256             TEXT NOT NULL,
  size_bytes         BIGINT NOT NULL,
  created_by         UUID REFERENCES users(id) ON DELETE SET NULL,
  requested_format   TEXT NOT NULL,             -- auto, or the format the uploader forced
  detected_format    TEXT NOT NULL,
  confidence         REAL,                      -- share of sampled lines that matched; NULL when forced
  total_lines        INT NOT NULL,
  parsed             INT NOT NULL,
  skipped            INT NOT NULL,
  inserted           INT NOT NULL,
  by_parser          JSONB NOT NULL DEFAULT '{}'::jsonb,
  skipped_reasons    JSONB NOT NULL DEFAULT '{}'::jsonb,
  skipped_samples    JSONB NOT NULL DEFAULT '[]'::jsonb,
  first_event_time   TIMESTAMPTZ,
  last_event_time    TIMESTAMPTZ,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_ingest_batches_created ON ingest_batches (created_at DESC);

ALTER TABLE events ADD COLUMN IF NOT EXISTS host       TEXT;
ALTER TABLE events ADD COLUMN IF NOT EXISTS event_code TEXT;   -- Windows EventID, CEF signature id, vendor log id
ALTER TABLE events ADD COLUMN IF NOT EXISTS outcome    TEXT;   -- success | failure | unknown
ALTER TABLE events ADD COLUMN IF NOT EXISTS protocol   TEXT;
ALTER TABLE events ADD COLUMN IF NOT EXISTS src_port   INT;
ALTER TABLE events ADD COLUMN IF NOT EXISTS parser     TEXT;   -- which parser produced the event
ALTER TABLE events ADD COLUMN IF NOT EXISTS batch_id   UUID REFERENCES ingest_batches(id) ON DELETE SET NULL;

-- Plain CREATE INDEX (not CONCURRENTLY) briefly blocks writes to events while
-- it builds. Fine at this project's volume; a large production table would
-- want one no-transaction migration per index instead.
CREATE INDEX IF NOT EXISTS idx_events_source_type_time ON events (source_type, event_time DESC);
CREATE INDEX IF NOT EXISTS idx_events_ingested          ON events (ingested_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_batch             ON events (batch_id) WHERE batch_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_events_event_code        ON events (event_code) WHERE event_code IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_events_username_time     ON events (username, event_time DESC) WHERE username IS NOT NULL;

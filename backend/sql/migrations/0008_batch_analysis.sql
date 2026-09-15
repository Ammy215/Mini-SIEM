-- Detection over an uploaded file's own time range. Live detection only looks
-- back a few minutes, so a log with last month's dates was stored but never
-- checked. An upload can now be queued for analysis; the scheduler picks it up
-- under the detection lease and records the outcome here.
ALTER TABLE ingest_batches ADD COLUMN IF NOT EXISTS detection_status TEXT NOT NULL DEFAULT 'none'
  CHECK (detection_status IN ('none', 'queued', 'running', 'done', 'failed'));
ALTER TABLE ingest_batches ADD COLUMN IF NOT EXISTS detection_requested_at TIMESTAMPTZ;
ALTER TABLE ingest_batches ADD COLUMN IF NOT EXISTS detection_requested_by UUID REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE ingest_batches ADD COLUMN IF NOT EXISTS detection_started_at TIMESTAMPTZ;
ALTER TABLE ingest_batches ADD COLUMN IF NOT EXISTS detection_finished_at TIMESTAMPTZ;
ALTER TABLE ingest_batches ADD COLUMN IF NOT EXISTS detection_result JSONB;
ALTER TABLE ingest_batches ADD COLUMN IF NOT EXISTS detection_error TEXT;
CREATE INDEX IF NOT EXISTS idx_ingest_batches_queued
  ON ingest_batches (detection_requested_at) WHERE detection_status = 'queued';

-- Where an alert came from: the live scheduler, an upload's analysis, or an
-- admin's run over a past range.
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS origin TEXT NOT NULL DEFAULT 'live'
  CHECK (origin IN ('live', 'batch', 'range'));
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS batch_id UUID REFERENCES ingest_batches(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_alerts_batch ON alerts (batch_id) WHERE batch_id IS NOT NULL;

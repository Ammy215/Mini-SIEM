-- Built-in rules used to be re-seeded over the top on every startup, so an
-- edit made on the Rules page was silently undone by the next restart. These
-- columns let seeding tell a shipped rule nobody changed (kept in step with
-- the code) from one someone edited (left alone until an admin resets it).
ALTER TABLE rules ADD COLUMN IF NOT EXISTS origin TEXT NOT NULL DEFAULT 'builtin'
  CHECK (origin IN ('builtin', 'custom'));
ALTER TABLE rules ADD COLUMN IF NOT EXISTS user_modified BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE rules ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ;
ALTER TABLE rules ADD COLUMN IF NOT EXISTS updated_by UUID REFERENCES users(id);

-- No backfill needed: every existing row came from seeding, and seeding
-- overwrote any edit at each startup, so no row holds a user change today.
-- The defaults above (builtin, not modified) are accurate for all of them.

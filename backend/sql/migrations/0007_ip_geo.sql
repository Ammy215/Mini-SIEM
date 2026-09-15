-- Where public IPs are, cached for 30 days: country for the foreign_geo signal,
-- the Events country filter and the attack map. Joined at query time rather
-- than copied onto every event row.
CREATE TABLE IF NOT EXISTS ip_geo (
  ip         INET PRIMARY KEY,
  country    TEXT,             -- ISO 3166-1 alpha-2, NULL when the provider didn't say
  region     TEXT,
  city       TEXT,
  org        TEXT,
  source     TEXT NOT NULL,    -- ipinfo | abuseipdb
  fetched_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ip_geo_country ON ip_geo (country);

-- A provider that answered "rate limited" is left alone until `until`, shared
-- by every process instead of each one finding out again.
CREATE TABLE IF NOT EXISTS provider_backoff (
  provider TEXT PRIMARY KEY,
  until    TIMESTAMPTZ NOT NULL,
  reason   TEXT
);

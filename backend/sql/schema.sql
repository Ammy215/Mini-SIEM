CREATE EXTENSION IF NOT EXISTS pgcrypto;   -- for gen_random_uuid()

-- ---------- users & RBAC ----------
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  full_name TEXT,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  failed_login_count INT NOT NULL DEFAULT 0,
  locked_until TIMESTAMPTZ,
  last_login_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS roles (
  id SERIAL PRIMARY KEY,
  name TEXT UNIQUE NOT NULL            -- admin | analyst | viewer
);

CREATE TABLE IF NOT EXISTS user_roles (
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  role_id INT  REFERENCES roles(id)  ON DELETE CASCADE,
  PRIMARY KEY (user_id, role_id)
);

-- ---------- normalized events ----------
CREATE TABLE IF NOT EXISTS events (
  id BIGSERIAL PRIMARY KEY,
  event_time  TIMESTAMPTZ NOT NULL,
  ingested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  source_type TEXT NOT NULL,          -- ssh | nginx | apache | syslog | app | firewall
  source_ip   INET,
  dest_ip     INET,
  dest_port   INT,
  username    TEXT,
  action      TEXT,                   -- login_failed | login_success | request | blocked ...
  status_code INT,
  method      TEXT,
  url         TEXT,
  user_agent  TEXT,
  country     TEXT,
  raw_message TEXT,
  raw         JSONB
);
CREATE INDEX IF NOT EXISTS idx_events_time   ON events (event_time DESC);
CREATE INDEX IF NOT EXISTS idx_events_src    ON events (source_ip);
CREATE INDEX IF NOT EXISTS idx_events_action ON events (action);
CREATE INDEX IF NOT EXISTS idx_events_fts    ON events USING GIN (to_tsvector('english', coalesce(raw_message,'')));

-- ---------- detection rules ----------
CREATE TABLE IF NOT EXISTS rules (
  id SERIAL PRIMARY KEY,
  rule_key TEXT UNIQUE NOT NULL,
  title TEXT NOT NULL,
  description TEXT,
  rule_type TEXT NOT NULL,            -- threshold | signature
  severity TEXT NOT NULL,             -- low | medium | high | critical
  mitre_technique TEXT,               -- e.g. T1110
  definition JSONB NOT NULL,          -- threshold params OR match conditions
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------- incidents (grouped alerts) ----------
CREATE TABLE IF NOT EXISTS incidents (
  id BIGSERIAL PRIMARY KEY,
  title TEXT NOT NULL,
  source_ip INET,
  severity TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',
  alert_count INT NOT NULL DEFAULT 0,
  first_seen TIMESTAMPTZ,
  last_seen  TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------- alerts ----------
CREATE TABLE IF NOT EXISTS alerts (
  id BIGSERIAL PRIMARY KEY,
  rule_id INT REFERENCES rules(id),
  incident_id BIGINT REFERENCES incidents(id),
  title TEXT NOT NULL,
  severity TEXT NOT NULL,
  mitre_technique TEXT,
  source_ip INET,
  threat_score INT,                   -- 0-100
  status TEXT NOT NULL DEFAULT 'open', -- open | acknowledged | resolved | false_positive
  evidence JSONB,                     -- the events/counts that triggered it
  acknowledged_by UUID REFERENCES users(id),
  acknowledged_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_status  ON alerts (status);

-- ---------- enrichment cache ----------
CREATE TABLE IF NOT EXISTS ioc_cache (
  id BIGSERIAL PRIMARY KEY,
  indicator TEXT NOT NULL,
  indicator_type TEXT NOT NULL,       -- ip | domain | hash | url
  provider TEXT NOT NULL,             -- abuseipdb | otx | ipinfo | virustotal
  data JSONB NOT NULL,
  cached_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  UNIQUE (indicator, provider)
);

-- ---------- audit log ----------
CREATE TABLE IF NOT EXISTS audit_log (
  id BIGSERIAL PRIMARY KEY,
  user_id UUID REFERENCES users(id),
  action TEXT NOT NULL,
  detail JSONB,
  ip_address INET,
  user_agent TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO roles (name) VALUES ('admin'),('analyst'),('viewer')
  ON CONFLICT DO NOTHING;

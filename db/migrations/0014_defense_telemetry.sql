-- Phase 2: normalized, deliberately bounded security telemetry.
-- Additive migration. No raw security-event bodies or credentials are stored.
CREATE TABLE IF NOT EXISTS defense_events (
    id BIGSERIAL PRIMARY KEY,
    source TEXT NOT NULL CHECK (source IN ('suricata','wazuh','generic','ocsf')),
    external_id TEXT NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    ingested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    kind TEXT NOT NULL CHECK (kind IN ('network','authentication','endpoint','other')),
    outcome TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL DEFAULT '',
    src_ip TEXT NOT NULL DEFAULT '',
    dst_ip TEXT NOT NULL DEFAULT '',
    host TEXT NOT NULL DEFAULT '',
    username TEXT NOT NULL DEFAULT '',
    signature TEXT NOT NULL DEFAULT '',
    severity INTEGER NOT NULL CHECK (severity BETWEEN 0 AND 10),
    vendor_alert BOOLEAN NOT NULL DEFAULT FALSE,
    asset_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
    UNIQUE(source, external_id)
);
CREATE INDEX IF NOT EXISTS idx_defense_events_time ON defense_events(observed_at DESC,id DESC);
CREATE INDEX IF NOT EXISTS idx_defense_events_spray ON defense_events(src_ip,observed_at)
    WHERE kind='authentication' AND outcome='failure';

CREATE TABLE IF NOT EXISTS defense_alerts (
    id BIGSERIAL PRIMARY KEY,
    rule_id TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('low','medium','high','critical')),
    summary TEXT NOT NULL,
    event_id BIGINT NOT NULL REFERENCES defense_events(id) ON DELETE CASCADE,
    correlation_key TEXT NOT NULL,
    window_start TIMESTAMPTZ NOT NULL,
    asset_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(rule_id,correlation_key,window_start)
);
CREATE INDEX IF NOT EXISTS idx_defense_alerts_time ON defense_alerts(created_at DESC,id DESC);

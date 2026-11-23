-- PR #10: least-privilege collectors, per-device event provenance, rate budgets.
-- Credentials are random 256-bit secrets stored ONLY as SHA-256 hashes.
CREATE TABLE defense_collectors (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE CHECK (length(name) BETWEEN 3 AND 64),
    source TEXT NOT NULL CHECK (source IN ('suricata','wazuh','generic','ocsf')),
    token_hash TEXT NOT NULL CHECK (length(token_hash) = 64),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    rotated_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
);
CREATE TABLE defense_collector_audit (
    id BIGSERIAL PRIMARY KEY,
    collector_id BIGINT NOT NULL REFERENCES defense_collectors(id) ON DELETE RESTRICT,
    operation TEXT NOT NULL CHECK (operation IN ('created','rotated','revoked')),
    actor TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_defense_collector_audit_recent
    ON defense_collector_audit(collector_id,occurred_at DESC);
CREATE TABLE defense_collector_rate (
    collector_id BIGINT NOT NULL REFERENCES defense_collectors(id) ON DELETE RESTRICT,
    minute_start TIMESTAMPTZ NOT NULL,
    event_count INTEGER NOT NULL CHECK (event_count BETWEEN 0 AND 600),
    PRIMARY KEY (collector_id,minute_start)
);
-- Keep legacy admin-ingested rows as NULL, but deduplicate overlapping vendor
-- event IDs *per collector*, instead of merging unrelated sensor evidence.
ALTER TABLE defense_events
    ADD COLUMN collector_id BIGINT REFERENCES defense_collectors(id) ON DELETE RESTRICT;
ALTER TABLE defense_events
    DROP CONSTRAINT IF EXISTS defense_events_source_external_id_key;
CREATE UNIQUE INDEX uq_defense_events_per_collector_external
    ON defense_events(source,COALESCE(collector_id,0),external_id);
CREATE INDEX idx_defense_events_collector_recent
    ON defense_events(collector_id,ingested_at DESC,id DESC);
-- Legacy rows stay NULL; their uniqueness is preserved by COALESCE(...,0).

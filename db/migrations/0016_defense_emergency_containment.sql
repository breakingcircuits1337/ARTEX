-- Emergency Auto-Containment. Append-only migration; previous versions untouched.
-- No actions occur until the human operator arms this policy explicitly.
CREATE TABLE IF NOT EXISTS defense_emergency_control (
    id SMALLINT PRIMARY KEY CHECK (id = 1),
    paused BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    operator_reason TEXT NOT NULL DEFAULT 'Initially paused'
);
INSERT INTO defense_emergency_control(id,paused,operator_reason)
VALUES (1,TRUE,'Initially paused by default')
ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS defense_emergency_actions (
    id BIGSERIAL PRIMARY KEY,
    event_id BIGINT NOT NULL REFERENCES defense_events(id) ON DELETE RESTRICT,
    source_ip TEXT NOT NULL,
    destination_ip TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    explanation TEXT NOT NULL,
    backend TEXT NOT NULL CHECK (backend IN ('simulate','nftables')),
    status TEXT NOT NULL DEFAULT 'pending' CHECK (
        status IN ('pending','active','simulated','reverted','expired','failed')
    ),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    applied_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    reversed_at TIMESTAMPTZ,
    latency_ms BIGINT NOT NULL DEFAULT 0,
    outcome_detail TEXT NOT NULL DEFAULT '',
    UNIQUE(event_id, rule_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_defense_emergency_live_source
    ON defense_emergency_actions(source_ip)
    WHERE status IN ('pending','active');
CREATE INDEX IF NOT EXISTS idx_defense_emergency_recent
    ON defense_emergency_actions(created_at DESC,id DESC);
CREATE INDEX IF NOT EXISTS idx_defense_emergency_expiry
    ON defense_emergency_actions(expires_at)
    WHERE status IN ('pending','active');

-- Explicit operator undo prevents immediate automatic re-block of the same IP
-- for 30 minutes; the pause button prevents new actions globally.
CREATE TABLE IF NOT EXISTS defense_emergency_suppressions (
    source_ip TEXT PRIMARY KEY,
    suppress_until TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS defense_emergency_audit (
    id BIGSERIAL PRIMARY KEY,
    action_id BIGINT REFERENCES defense_emergency_actions(id) ON DELETE RESTRICT,
    event_type TEXT NOT NULL CHECK (event_type IN (
        'armed','paused','queued','simulated','applied',
        'apply_failed','reversed','revert_failed','expired'
    )),
    actor TEXT NOT NULL CHECK (actor IN ('policy-engine','console-admin')),
    detail TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_defense_emergency_audit
    ON defense_emergency_audit(occurred_at DESC,id DESC);

-- The application only INSERTs. This cannot resist an adversarial DB owner.
CREATE OR REPLACE FUNCTION defense_emergency_reject_audit_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'defense_emergency_audit is append-only';
END
$$;
DROP TRIGGER IF EXISTS defense_emergency_audit_immutable ON defense_emergency_audit;
CREATE TRIGGER defense_emergency_audit_immutable
BEFORE UPDATE OR DELETE ON defense_emergency_audit
FOR EACH ROW EXECUTE FUNCTION defense_emergency_reject_audit_mutation();

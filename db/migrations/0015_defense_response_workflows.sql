-- Phase 3: operator-controlled, audited manual response recommendations.
-- Additive only: do not modify 0014 or any previously published migration.
CREATE TABLE IF NOT EXISTS defense_cases (
    id BIGSERIAL PRIMARY KEY,
    alert_id BIGINT NOT NULL UNIQUE REFERENCES defense_alerts(id) ON DELETE RESTRICT,
    status TEXT NOT NULL DEFAULT 'open'
        CHECK (status IN ('open', 'investigating', 'resolved', 'dismissed')),
    opened_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    closed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_defense_cases_status
    ON defense_cases(status, updated_at DESC, id DESC);

CREATE TABLE IF NOT EXISTS defense_response_requests (
    id BIGSERIAL PRIMARY KEY,
    case_id BIGINT NOT NULL REFERENCES defense_cases(id) ON DELETE RESTRICT,
    playbook TEXT NOT NULL CHECK (
        playbook IN ('review_network_block', 'review_identity_controls',
                     'review_endpoint_isolation', 'collect_additional_evidence')),
    justification TEXT NOT NULL CHECK (length(justification) BETWEEN 12 AND 1200),
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'approved', 'rejected', 'simulated')),
    decision_reason TEXT NOT NULL DEFAULT '',
    decided_at TIMESTAMPTZ,
    simulated_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_defense_response_pending
    ON defense_response_requests(status, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_defense_response_case
    ON defense_response_requests(case_id, id DESC);

CREATE TABLE IF NOT EXISTS defense_case_audit (
    id BIGSERIAL PRIMARY KEY,
    case_id BIGINT NOT NULL REFERENCES defense_cases(id) ON DELETE RESTRICT,
    response_id BIGINT REFERENCES defense_response_requests(id) ON DELETE RESTRICT,
    event_type TEXT NOT NULL CHECK (
        event_type IN ('case_opened', 'case_triaged', 'response_proposed',
                       'response_approved', 'response_rejected', 'response_simulated')),
    actor TEXT NOT NULL DEFAULT 'console-admin',
    reason TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_defense_case_audit
    ON defense_case_audit(case_id, occurred_at DESC, id DESC);

-- Application writes only INSERTs to this evidence log. Trigger catches
-- accidental mutation even by the database-owning application role. Database
-- superusers/DDL owners can still override it; do not claim cryptographic WORM.
CREATE OR REPLACE FUNCTION defense_reject_audit_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'defense_case_audit is append-only';
END
$$;
DROP TRIGGER IF EXISTS defense_audit_immutable ON defense_case_audit;
CREATE TRIGGER defense_audit_immutable
BEFORE UPDATE OR DELETE ON defense_case_audit
FOR EACH ROW EXECUTE FUNCTION defense_reject_audit_mutation();

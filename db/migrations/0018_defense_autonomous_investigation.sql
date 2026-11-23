-- Phase 7: durable, bounded autonomous evidence-only investigations.
-- Existing migration checksums (0001-0017) remain untouched.
CREATE TABLE IF NOT EXISTS defense_investigation_control (
 id SMALLINT PRIMARY KEY CHECK(id=1),
 auto_intake BOOLEAN NOT NULL DEFAULT FALSE,
 paused BOOLEAN NOT NULL DEFAULT FALSE,
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO defense_investigation_control(id) VALUES(1) ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS defense_investigation_runs (
 id BIGSERIAL PRIMARY KEY,
 case_id BIGINT NOT NULL REFERENCES defense_cases(id) ON DELETE RESTRICT,
 trigger_kind TEXT NOT NULL CHECK(trigger_kind IN ('case_opened','auto_alert','operator')),
 status TEXT NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','running','completed','failed','cancelled')),
 attempts SMALLINT NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 3),
 lease_until TIMESTAMPTZ,
 engine_version TEXT NOT NULL DEFAULT 'deterministic-v1' CHECK(engine_version='deterministic-v1'),
 summary TEXT NOT NULL DEFAULT '',
 last_error TEXT NOT NULL DEFAULT '',
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 started_at TIMESTAMPTZ,
 completed_at TIMESTAMPTZ,
 UNIQUE(case_id,id)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_defense_investigation_one_active
 ON defense_investigation_runs(case_id) WHERE status IN ('queued','running');
CREATE INDEX IF NOT EXISTS idx_defense_investigation_queue
 ON defense_investigation_runs(status,created_at,id);
CREATE INDEX IF NOT EXISTS idx_defense_investigation_case
 ON defense_investigation_runs(case_id,id DESC);
CREATE INDEX IF NOT EXISTS idx_defense_investigation_intake_budget
 ON defense_investigation_runs(created_at)
 WHERE trigger_kind='auto_alert';

CREATE TABLE IF NOT EXISTS defense_investigation_findings (
 id BIGSERIAL PRIMARY KEY,
 run_id BIGINT NOT NULL REFERENCES defense_investigation_runs(id) ON DELETE RESTRICT,
 case_id BIGINT NOT NULL REFERENCES defense_cases(id) ON DELETE RESTRICT,
 category TEXT NOT NULL CHECK(category IN
  ('alert_context','corroboration','asset_context','technique_hypothesis','coverage_gap')),
 title TEXT NOT NULL CHECK(length(title) BETWEEN 1 AND 160),
 explanation TEXT NOT NULL CHECK(length(explanation) BETWEEN 12 AND 1200),
 confidence SMALLINT NOT NULL CHECK(confidence BETWEEN 0 AND 90),
 evidence_event_id BIGINT NOT NULL REFERENCES defense_events(id) ON DELETE RESTRICT,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 UNIQUE(run_id,category,evidence_event_id),
 FOREIGN KEY(case_id,run_id) REFERENCES defense_investigation_runs(case_id,id),
 FOREIGN KEY(case_id,evidence_event_id) REFERENCES defense_case_observations(case_id,event_id),
 UNIQUE(case_id,id)
);
CREATE INDEX IF NOT EXISTS idx_defense_investigation_findings_run
 ON defense_investigation_findings(run_id,id);

CREATE TABLE IF NOT EXISTS defense_investigation_reviews (
 id BIGSERIAL PRIMARY KEY,
 finding_id BIGINT NOT NULL UNIQUE REFERENCES defense_investigation_findings(id) ON DELETE RESTRICT,
 case_id BIGINT NOT NULL REFERENCES defense_cases(id) ON DELETE RESTRICT,
 verdict TEXT NOT NULL CHECK(verdict IN ('supported','refuted','needs_more_evidence')),
 reason TEXT NOT NULL CHECK(length(reason) BETWEEN 12 AND 1200),
 actor TEXT NOT NULL DEFAULT 'console-admin',
 reviewed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 FOREIGN KEY(case_id,finding_id) REFERENCES defense_investigation_findings(case_id,id)
);
CREATE INDEX IF NOT EXISTS idx_defense_investigation_reviews_case
 ON defense_investigation_reviews(case_id,reviewed_at DESC);

CREATE TABLE IF NOT EXISTS defense_investigation_audit (
 id BIGSERIAL PRIMARY KEY,
 run_id BIGINT NOT NULL REFERENCES defense_investigation_runs(id) ON DELETE RESTRICT,
 case_id BIGINT NOT NULL REFERENCES defense_cases(id) ON DELETE RESTRICT,
 event_type TEXT NOT NULL CHECK(event_type IN
  ('queued','started','completed','failed','cancelled','reviewed','control_changed')),
 actor TEXT NOT NULL CHECK(actor IN ('investigator','console-admin')),
 detail TEXT NOT NULL CHECK(length(detail) BETWEEN 1 AND 1200),
 occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 FOREIGN KEY(case_id,run_id) REFERENCES defense_investigation_runs(case_id,id)
);
CREATE INDEX IF NOT EXISTS idx_defense_investigation_audit_run
 ON defense_investigation_audit(run_id,occurred_at DESC,id DESC);

-- Findings, human verdicts and audit records are append-only. Admins or
-- table owners can alter this trigger; this is not cryptographic WORM.
CREATE OR REPLACE FUNCTION defense_reject_investigation_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 RAISE EXCEPTION 'investigation evidence is append-only';
END
$$;
DROP TRIGGER IF EXISTS defense_investigation_findings_immutable ON defense_investigation_findings;
CREATE TRIGGER defense_investigation_findings_immutable
 BEFORE UPDATE OR DELETE ON defense_investigation_findings
 FOR EACH ROW EXECUTE FUNCTION defense_reject_investigation_mutation();
DROP TRIGGER IF EXISTS defense_investigation_reviews_immutable ON defense_investigation_reviews;
CREATE TRIGGER defense_investigation_reviews_immutable
 BEFORE UPDATE OR DELETE ON defense_investigation_reviews
 FOR EACH ROW EXECUTE FUNCTION defense_reject_investigation_mutation();
DROP TRIGGER IF EXISTS defense_investigation_audit_immutable ON defense_investigation_audit;
CREATE TRIGGER defense_investigation_audit_immutable
 BEFORE UPDATE OR DELETE ON defense_investigation_audit
 FOR EACH ROW EXECUTE FUNCTION defense_reject_investigation_mutation();

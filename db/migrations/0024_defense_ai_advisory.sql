-- PR #14: operator-requested AI advice is separate from deterministic findings.
-- No changes to auto-intake, emergency authorization, response or agent tools.
CREATE TABLE defense_ai_review_runs (
 id BIGSERIAL PRIMARY KEY,
 case_id BIGINT NOT NULL REFERENCES defense_cases(id) ON DELETE RESTRICT,
 status TEXT NOT NULL DEFAULT 'running'
   CHECK(status IN ('running','completed','failed')),
 engine TEXT NOT NULL DEFAULT 'review-v1' CHECK(engine='review-v1'),
 model_source TEXT NOT NULL DEFAULT 'configured-provider'
   CHECK(model_source='configured-provider'),
 packet_sha256 TEXT NOT NULL CHECK(packet_sha256 ~ '^[0-9a-f]{64}$'),
 summary TEXT NOT NULL DEFAULT '' CHECK(length(summary)<=500),
 error_code TEXT NOT NULL DEFAULT ''
   CHECK(error_code IN ('','provider_error','invalid_output','case_closed')),
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 completed_at TIMESTAMPTZ,
 UNIQUE(id,case_id)
);
CREATE UNIQUE INDEX idx_defense_ai_one_active_per_case
 ON defense_ai_review_runs(case_id) WHERE status='running';
CREATE INDEX idx_defense_ai_case_recent
 ON defense_ai_review_runs(case_id,created_at DESC,id DESC);
CREATE INDEX idx_defense_ai_global_budget
 ON defense_ai_review_runs(created_at DESC);

CREATE TABLE defense_ai_review_findings (
 id BIGSERIAL PRIMARY KEY,
 run_id BIGINT NOT NULL,
 case_id BIGINT NOT NULL,
 evidence_event_id BIGINT NOT NULL,
 category TEXT NOT NULL CHECK(category IN
   ('verification_gap','corroboration','alternative_explanation')),
 explanation TEXT NOT NULL CHECK(length(explanation) BETWEEN 18 AND 400),
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 UNIQUE(id,case_id),
 FOREIGN KEY(run_id,case_id) REFERENCES defense_ai_review_runs(id,case_id) ON DELETE RESTRICT,
 FOREIGN KEY(case_id,evidence_event_id) REFERENCES defense_case_observations(case_id,event_id)
   ON DELETE RESTRICT
);
CREATE INDEX idx_defense_ai_findings_run
 ON defense_ai_review_findings(run_id,id);

CREATE TABLE defense_ai_review_decisions (
 id BIGSERIAL PRIMARY KEY,
 finding_id BIGINT NOT NULL UNIQUE,
 case_id BIGINT NOT NULL,
 verdict TEXT NOT NULL CHECK(verdict IN ('supported','refuted','needs_more_evidence')),
 reason TEXT NOT NULL CHECK(length(reason) BETWEEN 12 AND 1200),
 actor TEXT NOT NULL DEFAULT 'console-admin' CHECK(actor='console-admin'),
 reviewed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 FOREIGN KEY(finding_id,case_id) REFERENCES defense_ai_review_findings(id,case_id)
   ON DELETE RESTRICT
);

CREATE TABLE defense_ai_review_audit (
 id BIGSERIAL PRIMARY KEY,
 run_id BIGINT NOT NULL REFERENCES defense_ai_review_runs(id) ON DELETE RESTRICT,
 event_type TEXT NOT NULL CHECK(event_type IN
   ('requested','completed','failed','reviewed')),
 actor TEXT NOT NULL CHECK(actor IN ('console-admin','ai-advisory')),
 detail_code TEXT NOT NULL CHECK(detail_code IN
   ('manual_consent','advice_persisted','provider_error','invalid_output',
    'case_closed','human_verdict')),
 occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_defense_ai_audit_run ON defense_ai_review_audit(run_id,id DESC);

-- Also enforce company evidence boundaries for all future direct SQL attempts,
-- including legacy cases from before explicit collector/company binding.
CREATE OR REPLACE FUNCTION defense_ai_finding_scope_guard()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
 anchor_event_id BIGINT;
 anchor_company_id BIGINT;
 evidence_company_id BIGINT;
BEGIN
 SELECT a.event_id,e.company_id INTO anchor_event_id,anchor_company_id
 FROM defense_cases c
 JOIN defense_alerts a ON a.id=c.alert_id
 JOIN defense_events e ON e.id=a.event_id
 WHERE c.id=NEW.case_id;
 SELECT company_id INTO evidence_company_id
 FROM defense_events WHERE id=NEW.evidence_event_id;
 IF anchor_event_id IS NULL
    OR (anchor_company_id IS NULL AND NEW.evidence_event_id<>anchor_event_id)
    OR (anchor_company_id IS NOT NULL
        AND (evidence_company_id IS NULL OR evidence_company_id<>anchor_company_id))
 THEN
    RAISE EXCEPTION 'AI review evidence is outside the case company scope';
 END IF;
 RETURN NEW;
END
$$;
CREATE TRIGGER defense_ai_finding_scope
 BEFORE INSERT OR UPDATE ON defense_ai_review_findings
 FOR EACH ROW EXECUTE FUNCTION defense_ai_finding_scope_guard();

-- AI text, human decisions and audit must not be rewritten or deleted.
CREATE OR REPLACE FUNCTION defense_ai_reject_immutable()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 RAISE EXCEPTION 'AI review evidence is append-only';
END
$$;
CREATE TRIGGER defense_ai_findings_immutable
 BEFORE UPDATE OR DELETE ON defense_ai_review_findings
 FOR EACH ROW EXECUTE FUNCTION defense_ai_reject_immutable();
CREATE TRIGGER defense_ai_decisions_immutable
 BEFORE UPDATE OR DELETE ON defense_ai_review_decisions
 FOR EACH ROW EXECUTE FUNCTION defense_ai_reject_immutable();
CREATE TRIGGER defense_ai_audit_immutable
 BEFORE UPDATE OR DELETE ON defense_ai_review_audit
 FOR EACH ROW EXECUTE FUNCTION defense_ai_reject_immutable();
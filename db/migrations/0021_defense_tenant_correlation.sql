-- PR #11: explicit company-scoped security evidence and safe cross-sensor links.
-- Additive migration; existing unassigned collectors and legacy events stay NULL.
-- Never infer a company retrospectively from an IP, vendor event or asset_ids JSON.
ALTER TABLE defense_collectors
  ADD COLUMN company_id BIGINT REFERENCES companies(id) ON DELETE RESTRICT;
ALTER TABLE defense_events
  ADD COLUMN company_id BIGINT REFERENCES companies(id) ON DELETE RESTRICT;

-- Fast scoped correlation; unscoped evidence is not eligible for cross-sensor matching.
CREATE INDEX idx_defense_events_company_time
  ON defense_events(company_id,observed_at DESC,id DESC)
  WHERE company_id IS NOT NULL;
CREATE INDEX idx_defense_events_company_pair
  ON defense_events(company_id,src_ip,dst_ip,observed_at DESC,id DESC)
  WHERE company_id IS NOT NULL AND src_ip<>'';
CREATE INDEX idx_defense_events_company_host
  ON defense_events(company_id,src_ip,host,observed_at DESC,id DESC)
  WHERE company_id IS NOT NULL AND src_ip<>'' AND host<>'';
CREATE INDEX idx_defense_collectors_company ON defense_collectors(company_id,id)
  WHERE company_id IS NOT NULL;

-- Audit every one-way company binding of an existing unbound collector.
ALTER TABLE defense_collector_audit
  DROP CONSTRAINT IF EXISTS defense_collector_audit_operation_check;
ALTER TABLE defense_collector_audit
  ADD CONSTRAINT defense_collector_audit_operation_check
  CHECK (operation IN ('created','rotated','revoked','bound'));

-- New links are investigative hypotheses; never permissions/automatic actions.
ALTER TABLE defense_case_observations
  DROP CONSTRAINT IF EXISTS defense_case_observations_link_reason_check;
ALTER TABLE defense_case_observations
  ADD CONSTRAINT defense_case_observations_link_reason_check
  CHECK (link_reason IN ('alert_anchor','same_source_and_endpoints',
    'same_source_and_host_ip','independent_collector_endpoints',
    'independent_collector_host_ip'));

-- SQL enforcement for new observations, including direct SQL insertions:
-- unscoped anchors accept ONLY unscoped evidence, and scoped anchors accept
-- only events with the same company ID. Prior historical observations are
-- deliberately retained for audit; the read APIs must still treat them as
-- untrusted legacy links if they lack a company assignment.
CREATE OR REPLACE FUNCTION defense_case_scope_guard()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE anchor_company BIGINT;
DECLARE candidate_company BIGINT;
BEGIN
  SELECT e.company_id INTO anchor_company
    FROM defense_cases c JOIN defense_alerts a ON a.id=c.alert_id
    JOIN defense_events e ON e.id=a.event_id
    WHERE c.id=NEW.case_id;
  SELECT company_id INTO candidate_company FROM defense_events
    WHERE id=NEW.event_id;
  IF anchor_company IS DISTINCT FROM candidate_company THEN
    RAISE EXCEPTION 'cross-company case observation prohibited';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER defense_case_scope_insert
BEFORE INSERT ON defense_case_observations
FOR EACH ROW EXECUTE FUNCTION defense_case_scope_guard();

-- Reject a mismatch even when a future import path writes directly to SQL.
-- Unbound historical collectors with NULL company still satisfy the check;
-- the public collector HTTP endpoint refuses them until bound.
CREATE OR REPLACE FUNCTION defense_event_company_guard()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE bound_company BIGINT;
BEGIN
  IF NEW.collector_id IS NOT NULL THEN
    SELECT c.company_id INTO bound_company FROM defense_collectors c
      WHERE c.id=NEW.collector_id;
    IF bound_company IS DISTINCT FROM NEW.company_id THEN
      RAISE EXCEPTION 'event company differs from enrolled collector company';
    END IF;
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER defense_event_company_insert
  BEFORE INSERT OR UPDATE OF collector_id,company_id ON defense_events
  FOR EACH ROW EXECUTE FUNCTION defense_event_company_guard();

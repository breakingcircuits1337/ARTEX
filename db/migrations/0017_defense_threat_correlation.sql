-- Phase 6: case-scoped, explainable security correlation graph.
-- Additive only. Published migrations 0001-0016 must never be edited.
-- Evidence links represent co-observation, not attribution or causality.

CREATE TABLE IF NOT EXISTS defense_case_observations (
    case_id BIGINT NOT NULL REFERENCES defense_cases(id) ON DELETE RESTRICT,
    event_id BIGINT NOT NULL REFERENCES defense_events(id) ON DELETE RESTRICT,
    link_reason TEXT NOT NULL CHECK (link_reason IN ('alert_anchor','same_source_and_endpoints','same_source_and_host_ip')),
    linkage_confidence SMALLINT NOT NULL CHECK (linkage_confidence BETWEEN 0 AND 100),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (case_id,event_id)
);
CREATE INDEX IF NOT EXISTS idx_defense_observations_event ON defense_case_observations(event_id,case_id);

CREATE TABLE IF NOT EXISTS defense_case_indicators (
    id BIGSERIAL PRIMARY KEY,
    case_id BIGINT NOT NULL REFERENCES defense_cases(id) ON DELETE RESTRICT,
    indicator_type TEXT NOT NULL CHECK (indicator_type IN ('ip','host','signature')),
    indicator_value TEXT NOT NULL CHECK (length(indicator_value) BETWEEN 1 AND 256),
    confidence SMALLINT NOT NULL CHECK (confidence BETWEEN 0 AND 100),
    confidence_meaning TEXT NOT NULL DEFAULT 'observation_linkage'
        CHECK (confidence_meaning='observation_linkage'),
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    first_event_id BIGINT NOT NULL REFERENCES defense_events(id) ON DELETE RESTRICT,
    UNIQUE(case_id,indicator_type,indicator_value),
    UNIQUE(case_id,id),
    FOREIGN KEY(case_id,first_event_id) REFERENCES defense_case_observations(case_id,event_id),
    CHECK(first_seen<=last_seen)
);
CREATE INDEX IF NOT EXISTS idx_defense_indicators_case ON defense_case_indicators(case_id,id);

CREATE TABLE IF NOT EXISTS defense_indicator_evidence (
    indicator_id BIGINT NOT NULL REFERENCES defense_case_indicators(id) ON DELETE RESTRICT,
    case_id BIGINT NOT NULL REFERENCES defense_cases(id) ON DELETE RESTRICT,
    event_id BIGINT NOT NULL REFERENCES defense_events(id) ON DELETE RESTRICT,
    evidence_role TEXT NOT NULL CHECK(evidence_role IN ('source_ip','destination_ip','host','sensor_signature')),
    observed_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY(indicator_id,event_id,evidence_role),
    FOREIGN KEY(case_id,event_id) REFERENCES defense_case_observations(case_id,event_id),
    FOREIGN KEY(case_id,indicator_id) REFERENCES defense_case_indicators(case_id,id)
);
CREATE INDEX IF NOT EXISTS idx_defense_indicator_evidence_case
    ON defense_indicator_evidence(case_id,event_id);

CREATE TABLE IF NOT EXISTS defense_case_relations (
    id BIGSERIAL PRIMARY KEY,
    case_id BIGINT NOT NULL REFERENCES defense_cases(id) ON DELETE RESTRICT,
    source_indicator_id BIGINT NOT NULL REFERENCES defense_case_indicators(id) ON DELETE RESTRICT,
    target_indicator_id BIGINT NOT NULL REFERENCES defense_case_indicators(id) ON DELETE RESTRICT,
    relation TEXT NOT NULL DEFAULT 'co_observed' CHECK(relation='co_observed'),
    evidence_event_id BIGINT NOT NULL REFERENCES defense_events(id) ON DELETE RESTRICT,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK(source_indicator_id<target_indicator_id),
    UNIQUE(case_id,source_indicator_id,target_indicator_id,evidence_event_id),
    FOREIGN KEY(case_id,evidence_event_id) REFERENCES defense_case_observations(case_id,event_id),
    FOREIGN KEY(case_id,source_indicator_id) REFERENCES defense_case_indicators(case_id,id),
    FOREIGN KEY(case_id,target_indicator_id) REFERENCES defense_case_indicators(case_id,id)
);
CREATE INDEX IF NOT EXISTS idx_defense_relations_case ON defense_case_relations(case_id,id);

CREATE TABLE IF NOT EXISTS defense_case_techniques (
    id BIGSERIAL PRIMARY KEY,
    case_id BIGINT NOT NULL REFERENCES defense_cases(id) ON DELETE RESTRICT,
    technique_id TEXT NOT NULL CHECK(technique_id ~ '^T[0-9]{4}([.][0-9]{3})?$'),
    tactic_id TEXT NOT NULL DEFAULT '' CHECK(tactic_id='' OR tactic_id ~ '^TA[0-9]{4}$'),
    confidence SMALLINT NOT NULL CHECK(confidence BETWEEN 0 AND 100),
    mapping_source TEXT NOT NULL CHECK(mapping_source IN ('rule_hint','analyst_hypothesis')),
    rationale TEXT NOT NULL CHECK(length(rationale) BETWEEN 12 AND 1200),
    evidence_event_id BIGINT NOT NULL REFERENCES defense_events(id) ON DELETE RESTRICT,
    mapped_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(case_id,technique_id,evidence_event_id,mapping_source),
    FOREIGN KEY(case_id,evidence_event_id) REFERENCES defense_case_observations(case_id,event_id)
);
CREATE INDEX IF NOT EXISTS idx_defense_techniques_case ON defense_case_techniques(case_id,mapped_at DESC,id DESC);

CREATE TABLE IF NOT EXISTS defense_case_intel_audit (
    id BIGSERIAL PRIMARY KEY,
    case_id BIGINT NOT NULL REFERENCES defense_cases(id) ON DELETE RESTRICT,
    audit_kind TEXT NOT NULL CHECK(audit_kind IN ('refreshed','technique_mapped')),
    actor TEXT NOT NULL CHECK(actor IN ('correlator','console-admin')),
    detail TEXT NOT NULL CHECK(length(detail) BETWEEN 1 AND 1200),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_defense_intel_audit_case
    ON defense_case_intel_audit(case_id,recorded_at DESC,id DESC);

CREATE OR REPLACE FUNCTION defense_reject_intel_audit_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'defense_case_intel_audit is append-only';
END
$$;
DROP TRIGGER IF EXISTS defense_intel_audit_immutable ON defense_case_intel_audit;
CREATE TRIGGER defense_intel_audit_immutable
BEFORE UPDATE OR DELETE ON defense_case_intel_audit
FOR EACH ROW EXECUTE FUNCTION defense_reject_intel_audit_mutation();

-- Bounded, same-source, two-field event correlation benefits from these
-- indexes. The case correlation query never scans arbitrary remote assets.
CREATE INDEX IF NOT EXISTS idx_defense_events_source_pair_time
  ON defense_events(source,src_ip,dst_ip,observed_at DESC,id DESC)
  WHERE src_ip<>'' AND dst_ip<>'';
CREATE INDEX IF NOT EXISTS idx_defense_events_source_host_time
  ON defense_events(source,host,src_ip,observed_at DESC,id DESC)
  WHERE host<>'' AND src_ip<>'';

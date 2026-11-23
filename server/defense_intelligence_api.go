package server

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/Autumn-27/artex/defense"
)

func (s *Server) refreshDefenseIntelligence(w http.ResponseWriter, r *http.Request) {
	if !s.defenseMode(w) {
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := workflowID(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	tx, err := pg.BeginTx(ctx, nil)
	if err != nil {
		writeErr(w, 503, "correlation store unavailable")
		return
	}
	defer tx.Rollback()
	counts, err := correlateDefenseCase(ctx, tx, id, "console-admin")
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, 404, "case not found")
		return
	}
	if err != nil {
		writeErr(w, 503, "case correlation failed")
		return
	}
	if err := tx.Commit(); err != nil {
		writeErr(w, 503, "correlation commit failed")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{
		"case_id": id, "reviewed": counts, "execution": false,
		"note": "Evidence-only co-observations; correlations do not trigger firewall, EDR, identity or agent actions.",
	})
}

// An operator may propose a hypothesis only for an event already linked to
// the same case. Tactic/technique ID syntax is not validation of ATT&CK
// catalog membership and does not establish verified malicious behavior.
func (s *Server) mapDefenseTechnique(w http.ResponseWriter, r *http.Request) {
	if !s.defenseMode(w) {
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := workflowID(w, r)
	if !ok {
		return
	}
	var input struct {
		TechniqueID string `json:"technique_id"`
		TacticID    string `json:"tactic_id"`
		EventID     int64  `json:"event_id"`
		Confidence  int    `json:"confidence"`
		Reason      string `json:"reason"`
	}
	if !decodeDefenseWorkflow(w, r, &input) {
		return
	}
	reason, err := defense.ValidateATTACKHypothesis(input.TechniqueID, input.TacticID, input.Confidence, input.Reason)
	if err != nil || input.EventID <= 0 {
		writeErr(w, 400, "invalid technique hypothesis, evidence ID, confidence or rationale")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	tx, err := pg.BeginTx(ctx, nil)
	if err != nil {
		writeErr(w, 503, "technique store unavailable")
		return
	}
	defer tx.Rollback()
	var status string
	if err := tx.QueryRowContext(ctx, `SELECT status FROM defense_cases WHERE id=$1 FOR UPDATE`, id).
		Scan(&status); errors.Is(err, sql.ErrNoRows) {
		writeErr(w, 404, "case not found")
		return
	} else if err != nil {
		writeErr(w, 503, "case unavailable")
		return
	}
	if !defense.ActiveCase(status) {
		writeErr(w, 409, "cannot add hypotheses to closed or dismissed cases")
		return
	}
	var linked bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS(SELECT 1 FROM defense_case_observations
		WHERE case_id=$1 AND event_id=$2)`, id, input.EventID).Scan(&linked); err != nil {
		writeErr(w, 503, "case evidence lookup failed")
		return
	}
	if !linked {
		writeErr(w, 409, "evidence event is not linked to this case; refresh correlation first")
		return
	}
	var mappingID int64
	err = tx.QueryRowContext(ctx, `
		INSERT INTO defense_case_techniques
		(case_id,technique_id,tactic_id,confidence,mapping_source,rationale,evidence_event_id)
		VALUES($1,$2,$3,$4,'analyst_hypothesis',$5,$6)
		ON CONFLICT DO NOTHING RETURNING id`,
		id, input.TechniqueID, input.TacticID, input.Confidence, reason, input.EventID).Scan(&mappingID)
	created := err == nil
	if errors.Is(err, sql.ErrNoRows) {
		err = tx.QueryRowContext(ctx, `
			SELECT id FROM defense_case_techniques
			 WHERE case_id=$1 AND technique_id=$2
			   AND evidence_event_id=$3 AND mapping_source='analyst_hypothesis'`,
			id, input.TechniqueID, input.EventID).Scan(&mappingID)
	}
	if err != nil {
		writeErr(w, 503, "technique mapping persistence failed")
		return
	}
	if created {
		detail := fmt.Sprintf("Analyst proposed %s / %s at %d/100 linkage confidence for event #%d: %s",
			input.TechniqueID, input.TacticID, input.Confidence, input.EventID, reason)
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO defense_case_intel_audit(case_id,audit_kind,actor,detail)
			VALUES($1,'technique_mapped','console-admin',$2)`, id, detail); err != nil {
			writeErr(w, 503, "technique audit failed")
			return
		}
	}
	if err := tx.Commit(); err != nil {
		writeErr(w, 503, "technique commit failed")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{
		"id": mappingID, "case_id": id, "created": created,
		"mapping_source": "analyst_hypothesis",
		"verified_compromise": false, "execution": false,
	})
}

func (s *Server) getDefenseIntelligence(w http.ResponseWriter, r *http.Request) {
	if !s.defenseMode(w) {
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := workflowID(w, r)
	if !ok {
		return
	}
	var exists bool
	if err := pg.QueryRowContext(r.Context(),
		`SELECT EXISTS(SELECT 1 FROM defense_cases WHERE id=$1)`, id).Scan(&exists); err != nil {
		writeErr(w, 503, "correlation lookup failed")
		return
	}
	if !exists {
		writeErr(w, 404, "case not found")
		return
	}
	rows, err := pg.QueryContext(r.Context(), `
		SELECT i.id,i.indicator_type,i.indicator_value,i.confidence,
		       i.confidence_meaning,i.first_seen,i.last_seen,i.first_event_id,
		       (SELECT count(*) FROM defense_indicator_evidence ev WHERE ev.indicator_id=i.id)
		  FROM defense_case_indicators i WHERE i.case_id=$1 ORDER BY i.id LIMIT 250`, id)
	if err != nil {
		writeErr(w, 503, "indicator store unavailable")
		return
	}
	indicators := make([]map[string]any, 0)
	for rows.Next() {
		var indicatorID, firstEvent, evidenceCount int64
		var kind, value, meaning string
		var confidence int
		var first, last time.Time
		if err := rows.Scan(&indicatorID, &kind, &value, &confidence, &meaning,
			&first, &last, &firstEvent, &evidenceCount); err != nil {
			rows.Close()
			writeErr(w, 503, "indicator scan failed")
			return
		}
		indicators = append(indicators, map[string]any{
			"id": indicatorID, "type": kind, "value": value,
			"confidence": confidence, "confidence_meaning": meaning,
			"first_seen": first, "last_seen": last,
			"first_event_id": firstEvent, "evidence_count": evidenceCount,
		})
	}
	scanErr := rows.Err()
	rows.Close()
	if scanErr != nil {
		writeErr(w, 503, "indicator iterator failed")
		return
	}
	rows, err = pg.QueryContext(r.Context(), `
		SELECT ev.indicator_id,ev.event_id,ev.evidence_role,ev.observed_at,
		       e.source,e.external_id
		  FROM defense_indicator_evidence ev
		  JOIN defense_events e ON e.id=ev.event_id
		 WHERE ev.case_id=$1 ORDER BY ev.event_id,ev.indicator_id LIMIT 250`, id)
	if err != nil {
		writeErr(w, 503, "indicator provenance unavailable")
		return
	}
	provenance := make([]map[string]any, 0)
	for rows.Next() {
		var indicatorID, eventID int64
		var role, source, external string
		var observed time.Time
		if err := rows.Scan(&indicatorID, &eventID, &role, &observed, &source, &external); err != nil {
			rows.Close()
			writeErr(w, 503, "provenance scan failed")
			return
		}
		provenance = append(provenance, map[string]any{
			"indicator_id": indicatorID, "event_id": eventID,
			"evidence_role": role, "observed_at": observed,
			"source": source, "external_id": external,
		})
	}
	scanErr = rows.Err()
	rows.Close()
	if scanErr != nil {
		writeErr(w, 503, "provenance iterator failed")
		return
	}
	rows, err = pg.QueryContext(r.Context(), `
		SELECT o.event_id,o.link_reason,o.linkage_confidence,o.recorded_at,
		       e.source,e.external_id,e.kind,e.observed_at,e.src_ip,e.dst_ip,e.host
		  FROM defense_case_observations o
		  JOIN defense_events e ON e.id=o.event_id
		 WHERE o.case_id=$1 ORDER BY e.observed_at ASC,e.id ASC LIMIT 100`, id)
	if err != nil {
		writeErr(w, 503, "observation store unavailable")
		return
	}
	observations := make([]map[string]any, 0)
	for rows.Next() {
		var eventID int64
		var reason, source, externalID, kind, src, dst, host string
		var confidence int
		var recorded, observed time.Time
		if err := rows.Scan(&eventID, &reason, &confidence, &recorded,
			&source, &externalID, &kind, &observed, &src, &dst, &host); err != nil {
			rows.Close()
			writeErr(w, 503, "observation scan failed")
			return
		}
		observations = append(observations, map[string]any{
			"event_id": eventID, "link_reason": reason,
			"linkage_confidence": confidence, "recorded_at": recorded,
			"source": source, "external_id": externalID, "kind": kind,
			"observed_at": observed, "src_ip": src, "dst_ip": dst, "host": host,
		})
	}
	scanErr = rows.Err()
	rows.Close()
	if scanErr != nil {
		writeErr(w, 503, "observation iterator failed")
		return
	}
	rows, err = pg.QueryContext(r.Context(), `
		SELECT id,technique_id,tactic_id,confidence,mapping_source,rationale,
		       evidence_event_id,mapped_at
		  FROM defense_case_techniques WHERE case_id=$1 ORDER BY id LIMIT 100`, id)
	if err != nil {
		writeErr(w, 503, "ATT&CK mappings unavailable")
		return
	}
	techniques := make([]map[string]any, 0)
	for rows.Next() {
		var mappingID, evidenceID int64
		var technique, tactic, source, rationale string
		var confidence int
		var mapped time.Time
		if err := rows.Scan(&mappingID, &technique, &tactic, &confidence,
			&source, &rationale, &evidenceID, &mapped); err != nil {
			rows.Close()
			writeErr(w, 503, "mapping scan failed")
			return
		}
		techniques = append(techniques, map[string]any{
			"id": mappingID, "technique_id": technique, "tactic_id": tactic,
			"confidence": confidence, "mapping_source": source,
			"rationale": rationale, "evidence_event_id": evidenceID,
			"mapped_at": mapped, "confirmed": false,
		})
	}
	scanErr = rows.Err()
	rows.Close()
	if scanErr != nil {
		writeErr(w, 503, "mapping iterator failed")
		return
	}
	rows, err = pg.QueryContext(r.Context(), `
		SELECT id,source_indicator_id,target_indicator_id,evidence_event_id,relation
		  FROM defense_case_relations WHERE case_id=$1 ORDER BY id LIMIT 250`, id)
	if err != nil {
		writeErr(w, 503, "indicator relations unavailable")
		return
	}
	relations := make([]map[string]any, 0)
	for rows.Next() {
		var relationID, sourceID, targetID, evidenceID int64
		var kind string
		if err := rows.Scan(&relationID, &sourceID, &targetID, &evidenceID, &kind); err != nil {
			rows.Close()
			writeErr(w, 503, "relation scan failed")
			return
		}
		relations = append(relations, map[string]any{
			"id": relationID, "source_indicator_id": sourceID,
			"target_indicator_id": targetID, "evidence_event_id": evidenceID,
			"relation": kind, "causal_claim": false,
		})
	}
	scanErr = rows.Err()
	rows.Close()
	if scanErr != nil {
		writeErr(w, 503, "relation iterator failed")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{
		"case_id": id, "mode": "read_only",
		"indicators": indicators, "observations": observations,
		"indicator_evidence": provenance, "relations": relations, "techniques": techniques,
		"note": "Confidence scores describe evidence linkage or analyst hypotheses, never probability of compromise. Evidence may be incomplete and correlation is not attribution.",
	})
}

// Timeline explicitly distinguishes the sensor's observed_at from the time
// an analyst or correlation engine appended its own record. A history entry
// never implies a threat actor or proves an exploitation path.
func (s *Server) getDefenseTimeline(w http.ResponseWriter, r *http.Request) {
	if !s.defenseMode(w) {
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := workflowID(w, r)
	if !ok {
		return
	}
	var exists bool
	if err := pg.QueryRowContext(r.Context(),
		`SELECT EXISTS(SELECT 1 FROM defense_cases WHERE id=$1)`, id).Scan(&exists); err != nil {
		writeErr(w, 503, "case lookup failed")
		return
	}
	if !exists {
		writeErr(w, 404, "case not found")
		return
	}
	rows, err := pg.QueryContext(r.Context(), `
		SELECT kind,reference_id,occurred_at,summary,provenance,confidence
		FROM (
		  SELECT kind,reference_id,occurred_at,summary,provenance,confidence
		  FROM (
		  SELECT 'sensor_event'::text AS kind, e.id AS reference_id,
		         e.observed_at AS occurred_at,
		         left(e.kind||' / '||o.link_reason,180) AS summary,
		         e.source||':'||e.external_id AS provenance,
		         o.linkage_confidence::int AS confidence
		    FROM defense_case_observations o
		    JOIN defense_events e ON e.id=o.event_id
		   WHERE o.case_id=$1
		  UNION ALL
		  SELECT 'case_audit',a.id,a.occurred_at,
		         left(a.event_type||': '||a.reason,180),
		         a.actor,0 FROM defense_case_audit a WHERE a.case_id=$1
		  UNION ALL
		  SELECT 'attack_hypothesis',m.id,m.mapped_at,
		         left(m.technique_id||' / '||m.tactic_id||': '||m.rationale,180),
		         m.mapping_source,m.confidence::int
		    FROM defense_case_techniques m WHERE m.case_id=$1
		  UNION ALL
		  SELECT 'intel_audit',a.id,a.recorded_at,
		         left(a.audit_kind||': '||a.detail,180),
		         a.actor,0 FROM defense_case_intel_audit a WHERE a.case_id=$1
		  ) AS history
		  ORDER BY occurred_at DESC,kind DESC,reference_id DESC LIMIT 250
		) AS recent
		ORDER BY occurred_at ASC,kind ASC,reference_id ASC`, id)
	if err != nil {
		writeErr(w, 503, "case timeline unavailable")
		return
	}
	defer rows.Close()
	entries := make([]map[string]any, 0)
	for rows.Next() {
		var kind, summary, source string
		var refID int64
		var occurred time.Time
		var confidence int
		if err := rows.Scan(&kind, &refID, &occurred, &summary, &source, &confidence); err != nil {
			writeErr(w, 503, "timeline scan failed")
			return
		}
		entries = append(entries, map[string]any{
			"kind": kind, "reference_id": refID, "occurred_at": occurred,
			"summary": summary, "provenance": source,
			"confidence": confidence,
		})
	}
	if rows.Err() != nil {
		writeErr(w, 503, "timeline iterator failed")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{
		"case_id": id, "events": entries, "limit": 250,
		"note": "Sensor occurrence timestamps and ingestion/audit timestamps come from different clocks; ordering does not prove causation.",
	})
}

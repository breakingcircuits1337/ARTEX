package server

import (
	"context"
	"fmt"
	"time"

	"github.com/Autumn-27/artex/db"
)

// appendCorrelationGraph augments the existing Phase 3 case-evidence graph
// with verified database links and clearly marked tentative hypotheses.
// No graph edge is treated as proof of causation, exploitation or attribution.
func appendCorrelationGraph(
	ctx context.Context, pg *db.DB, caseID int64,
	nodes *[]defenseGraphNode, edges *[]defenseGraphEdge,
) error {
	caseKey := fmt.Sprintf("case:%d", caseID)
	seen := map[string]bool{}
	for _, node := range *nodes {
		seen[node.ID] = true
	}
	addNode := func(node defenseGraphNode) {
		if !seen[node.ID] {
			*nodes = append(*nodes, node)
			seen[node.ID] = true
		}
	}
	rows, err := pg.QueryContext(ctx, `
		SELECT o.event_id,o.link_reason,o.linkage_confidence,
		       e.source,e.external_id,e.observed_at
		  FROM defense_case_observations o
		  JOIN defense_events e ON e.id=o.event_id
		 WHERE o.case_id=$1 ORDER BY e.observed_at DESC,e.id DESC LIMIT 100`, caseID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var eventID int64
		var reason, source, external string
		var confidence int
		var observed time.Time
		if err := rows.Scan(&eventID, &reason, &confidence,
			&source, &external, &observed); err != nil {
			rows.Close()
			return err
		}
		key := fmt.Sprintf("event:%d", eventID)
		addNode(defenseGraphNode{
			ID: key, Kind: "event", Label: source + " evidence #" + external,
			Metadata: map[string]any{
				"source": source, "source_event_id": external,
				"observed_at": observed, "linkage_confidence": confidence,
				"link_reason": reason, "verified_compromise": false,
			},
		})
		*edges = append(*edges, defenseGraphEdge{
			Source: caseKey, Target: key, Relation: "investigative_observation",
		})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	rows, err = pg.QueryContext(ctx, `
		SELECT i.id,i.indicator_type,i.indicator_value,i.confidence,
		       i.first_event_id,i.first_seen,i.last_seen
		  FROM defense_case_indicators i
		 WHERE i.case_id=$1 ORDER BY i.id LIMIT 250`, caseID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var id, firstEventID int64
		var kind, value string
		var confidence int
		var first, last time.Time
		if err := rows.Scan(&id, &kind, &value, &confidence, &firstEventID, &first, &last); err != nil {
			rows.Close()
			return err
		}
		key := fmt.Sprintf("indicator:%d", id)
		addNode(defenseGraphNode{ID: key, Kind: "observed_indicator",
			Label: kind + ": " + value,
			Metadata: map[string]any{
				"indicator_type": kind,
				"linkage_confidence": confidence,
				"first_seen": first, "last_seen": last,
				"verified_malicious": false,
			},
		})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	// Every indicator-to-event edge is backed by a strict case-local FK,
	// not just the first event which mentioned the value.
	rows, err = pg.QueryContext(ctx, `
		SELECT indicator_id,event_id,evidence_role
		FROM defense_indicator_evidence WHERE case_id=$1
		ORDER BY event_id,indicator_id LIMIT 250`, caseID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var indicatorID, eventID int64
		var role string
		if err := rows.Scan(&indicatorID, &eventID, &role); err != nil {
			rows.Close()
			return err
		}
		*edges = append(*edges, defenseGraphEdge{
			Source: fmt.Sprintf("event:%d", eventID),
			Target: fmt.Sprintf("indicator:%d", indicatorID),
			Relation: "observed_" + role,
		})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	rows, err = pg.QueryContext(ctx, `
		SELECT source_indicator_id,target_indicator_id,evidence_event_id
		FROM defense_case_relations WHERE case_id=$1 ORDER BY id LIMIT 250`, caseID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var sourceID, targetID, evidenceID int64
		if err := rows.Scan(&sourceID, &targetID, &evidenceID); err != nil {
			rows.Close()
			return err
		}
		*edges = append(*edges, defenseGraphEdge{
			Source: fmt.Sprintf("indicator:%d", sourceID),
			Target: fmt.Sprintf("indicator:%d", targetID),
			Relation: fmt.Sprintf("co_observed_event_%d", evidenceID),
		})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	rows, err = pg.QueryContext(ctx, `
		SELECT id,technique_id,tactic_id,mapping_source,confidence,
		       rationale,evidence_event_id,mapped_at
		  FROM defense_case_techniques WHERE case_id=$1 ORDER BY id LIMIT 100`, caseID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var id, evidenceID int64
		var technique, tactic, source, rationale string
		var confidence int
		var mapped time.Time
		if err := rows.Scan(&id, &technique, &tactic, &source, &confidence,
			&rationale, &evidenceID, &mapped); err != nil {
			rows.Close()
			return err
		}
		key := fmt.Sprintf("technique:%d", id)
		addNode(defenseGraphNode{ID: key, Kind: "attack_hypothesis",
			Label: technique + " / " + tactic, Metadata: map[string]any{
				"mapping_source": source,
				"confidence": confidence,
				"rationale": rationale,
				"mapped_at": mapped,
				"confirmed": false,
			},
		})
		*edges = append(*edges, defenseGraphEdge{
			Source: fmt.Sprintf("event:%d", evidenceID),
			Target: key, Relation: "suggests_not_proves",
		})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	return nil
}

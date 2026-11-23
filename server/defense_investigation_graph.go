package server

import (
	"context"
	"fmt"

	"github.com/Autumn-27/artex/db"
)

// appendInvestigationGraph adds reviewable autonomous findings to the existing
// Phase 3/6 graph. All links come from case-scoped database foreign keys.
// "supported" is an analyst review verdict, never proven maliciousness.
func appendInvestigationGraph(
	ctx context.Context, pg *db.DB, caseID int64,
	nodes *[]defenseGraphNode, edges *[]defenseGraphEdge,
) error {
	rows, err := pg.QueryContext(ctx, `
		SELECT id,status,trigger_kind,created_at
		FROM defense_investigation_runs WHERE case_id=$1
		ORDER BY id DESC LIMIT 20`, caseID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var id int64
		var status, trigger string
		var created any
		if err := rows.Scan(&id, &status, &trigger, &created); err != nil {
			rows.Close()
			return err
		}
		key := fmt.Sprintf("investigation:%d", id)
		*nodes = append(*nodes, defenseGraphNode{
			ID: key, Kind: "investigation", Label: "Deterministic investigation",
			Metadata: map[string]any{
				"status": status, "trigger": trigger, "started_by_llm": false,
				"response_executed": false, "created_at": created,
			},
		})
		*edges = append(*edges, defenseGraphEdge{
			Source: fmt.Sprintf("case:%d", caseID),
			Target: key, Relation: "evidence_review",
		})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	rows, err = pg.QueryContext(ctx, `
		SELECT f.id,f.run_id,f.category,f.title,f.confidence,
		       f.evidence_event_id,COALESCE(r.verdict,'')
		FROM defense_investigation_findings f
		LEFT JOIN defense_investigation_reviews r ON r.finding_id=f.id
		WHERE f.case_id=$1 ORDER BY f.id DESC LIMIT 120`, caseID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var id, runID, eventID int64
		var category, title, verdict string
		var confidence int
		if err := rows.Scan(&id, &runID, &category, &title,
			&confidence, &eventID, &verdict); err != nil {
			rows.Close()
			return err
		}
		key := fmt.Sprintf("investigation_finding:%d", id)
		*nodes = append(*nodes, defenseGraphNode{
			ID: key, Kind: "investigation_finding", Label: title,
			Metadata: map[string]any{
				"category": category, "confidence": confidence,
				"review_verdict": verdict, "verified_compromise": false,
				"response_authorized": false,
			},
		})
		*edges = append(*edges,
			defenseGraphEdge{Source: fmt.Sprintf("investigation:%d", runID),
				Target: key, Relation: "proposes_unverified"},
			defenseGraphEdge{Source: key, Target: fmt.Sprintf("event:%d", eventID),
				Relation: "cites_evidence"},
		)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	return rows.Close()
}

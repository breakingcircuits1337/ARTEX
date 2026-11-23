package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// defenseGraphNode is an evidence reference, not an active-scan target.
// IDs are stable across graph refreshes; relations are read-only.
type defenseGraphNode struct {
	ID       string         `json:"id"`
	Kind     string         `json:"kind"`
	Label    string         `json:"label"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

type defenseGraphEdge struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	Relation string `json:"relation"`
}

// GET /api/defense/cases/{id}/graph exposes a bounded incident-evidence graph.
// It reads only the already-stored case, linked alert/event, asset IDs,
// proposed manual responses, and operator audit entries.
func (s *Server) defenseCaseGraph(w http.ResponseWriter, r *http.Request) {
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
	var alertID, eventID int64
	var caseStatus, ruleID, title, severity, source, externalID string
	var observed time.Time
	var rawAssets []byte
	err := pg.QueryRowContext(r.Context(),
		`SELECT c.alert_id,c.status,a.rule_id,a.title,a.severity,a.event_id,a.asset_ids,
		        e.source,e.external_id,e.observed_at
		   FROM defense_cases c
		   JOIN defense_alerts a ON a.id=c.alert_id
		   JOIN defense_events e ON e.id=a.event_id
		  WHERE c.id=$1`, id).Scan(
		&alertID, &caseStatus, &ruleID, &title, &severity, &eventID, &rawAssets,
		&source, &externalID, &observed,
	)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, 404, "case not found")
		return
	}
	if err != nil {
		writeErr(w, 503, "incident graph unavailable")
		return
	}
	var assetIDs []int64
	if err := json.Unmarshal(rawAssets, &assetIDs); err != nil {
		writeErr(w, 503, "asset links invalid")
		return
	}
	caseKey := fmt.Sprintf("case:%d", id)
	alertKey := fmt.Sprintf("alert:%d", alertID)
	eventKey := fmt.Sprintf("event:%d", eventID)
	nodes := []defenseGraphNode{
		{ID: caseKey, Kind: "case", Label: "Incident case", Metadata: map[string]any{"status": caseStatus}},
		{ID: alertKey, Kind: "alert", Label: title, Metadata: map[string]any{"rule_id": ruleID, "severity": severity}},
		{ID: eventKey, Kind: "event", Label: "Normalized event", Metadata: map[string]any{
			"source": source, "source_event_id": externalID, "observed_at": observed,
		}},
	}
	edges := []defenseGraphEdge{
		{Source: caseKey, Target: alertKey, Relation: "investigates"},
		{Source: alertKey, Target: eventKey, Relation: "supported_by"},
	}
	for _, assetID := range assetIDs {
		key := fmt.Sprintf("asset:%d", assetID)
		nodes = append(nodes, defenseGraphNode{
			ID: key, Kind: "asset", Label: fmt.Sprintf("Inventory asset #%d", assetID),
		})
		edges = append(edges, defenseGraphEdge{
			Source: alertKey, Target: key, Relation: "correlates_with",
		})
	}

	rows, err := pg.QueryContext(r.Context(),
		`SELECT id,playbook,status FROM defense_response_requests
		  WHERE case_id=$1 ORDER BY id DESC LIMIT 100`, id)
	if err != nil {
		writeErr(w, 503, "response graph unavailable")
		return
	}
	for rows.Next() {
		var responseID int64
		var playbook, status string
		if err := rows.Scan(&responseID, &playbook, &status); err != nil {
			rows.Close()
			writeErr(w, 503, "response graph scan failed")
			return
		}
		key := fmt.Sprintf("response:%d", responseID)
		nodes = append(nodes, defenseGraphNode{ID: key, Kind: "manual_response", Label: playbook,
			Metadata: map[string]any{"status": status, "executed": false}})
		edges = append(edges, defenseGraphEdge{Source: caseKey, Target: key, Relation: "reviews"})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		writeErr(w, 503, "response graph iterator failed")
		return
	}
	rows.Close()
	rows, err = pg.QueryContext(r.Context(),
		`SELECT id,response_id,event_type FROM defense_case_audit
		  WHERE case_id=$1 ORDER BY id DESC LIMIT 100`, id)
	if err != nil {
		writeErr(w, 503, "audit graph unavailable")
		return
	}
	for rows.Next() {
		var auditID int64
		var responseID sql.NullInt64
		var kind string
		if err := rows.Scan(&auditID, &responseID, &kind); err != nil {
			rows.Close()
			writeErr(w, 503, "audit graph scan failed")
			return
		}
		key := fmt.Sprintf("audit:%d", auditID)
		nodes = append(nodes, defenseGraphNode{ID: key, Kind: "audit", Label: kind})
		target := caseKey
		if responseID.Valid {
			target = fmt.Sprintf("response:%d", responseID.Int64)
		}
		edges = append(edges, defenseGraphEdge{Source: key, Target: target, Relation: "records"})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		writeErr(w, 503, "audit graph iterator failed")
		return
	}
	rows.Close()
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{
		"case_id": id, "mode": "read_only", "nodes": nodes, "edges": edges,
		"note": "Graph edges are recorded-evidence links, not proof of compromise or causal attribution.",
	})
}

package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Autumn-27/artex/defense"
)

// Phase 3 is intentionally manual and never invokes an EDR, firewall,
// identity provider, shell or remote tool. Every state change is performed
// by the authenticated ARTEX console and logged in the same database TX.
const defenseWorkflowBodyLimit int64 = 4096

func decodeDefenseWorkflow(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, defenseWorkflowBodyLimit)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid workflow JSON")
		return false
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		writeErr(w, http.StatusBadRequest, "workflow JSON must contain exactly one object")
		return false
	}
	return true
}

func workflowReason(w http.ResponseWriter, raw string) (string, bool) {
	reason, err := defense.ValidateReason(raw)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return "", false
	}
	return reason, true
}

func workflowID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, http.StatusBadRequest, "invalid workflow ID")
		return 0, false
	}
	return id, true
}

// auditDefenseCase is called only inside the same transaction as its state
// change. The PostgreSQL trigger rejects UPDATE and DELETE on audit records.
func auditDefenseCase(ctx context.Context, tx *sql.Tx, caseID int64, responseID *int64, kind, reason string) error {
	_, err := tx.ExecContext(ctx,
		`INSERT INTO defense_case_audit (case_id, response_id, event_type, actor, reason)
		 VALUES ($1, $2, $3, 'console-admin', $4)`,
		caseID, responseID, kind, reason,
	)
	return err
}

// POST /api/defense/cases {alert_id}. Idempotent by alert ID.
func (s *Server) createDefenseCase(w http.ResponseWriter, r *http.Request) {
	if !s.defenseMode(w) {
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var input struct {
		AlertID int64 `json:"alert_id"`
	}
	if !decodeDefenseWorkflow(w, r, &input) {
		return
	}
	if input.AlertID <= 0 {
		writeErr(w, 400, "alert_id must be positive")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	tx, err := pg.BeginTx(ctx, nil)
	if err != nil {
		writeErr(w, 503, "case database unavailable")
		return
	}
	defer tx.Rollback()
	var alertID int64
	if err := tx.QueryRowContext(ctx, `SELECT id FROM defense_alerts WHERE id=$1`, input.AlertID).Scan(&alertID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, 404, "alert not found")
		} else {
			writeErr(w, 503, "alert lookup failed")
		}
		return
	}
	var id int64
	err = tx.QueryRowContext(ctx,
		`INSERT INTO defense_cases(alert_id) VALUES($1)
		 ON CONFLICT(alert_id) DO NOTHING RETURNING id`,
		alertID,
	).Scan(&id)
	created := err == nil
	if errors.Is(err, sql.ErrNoRows) {
		err = tx.QueryRowContext(ctx, `SELECT id FROM defense_cases WHERE alert_id=$1`, alertID).Scan(&id)
	}
	if err != nil {
		writeErr(w, 503, "case creation failed")
		return
	}
	if created {
		if err := auditDefenseCase(ctx, tx, id, nil, "case_opened", "Opened from normalized security alert"); err != nil {
			writeErr(w, 503, "case audit unavailable")
			return
		}
	}
	if err := tx.Commit(); err != nil {
		writeErr(w, 503, "case commit failed")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "alert_id": alertID, "created": created})
}

// GET /api/defense/cases. Cases remain linked to the original alert + event,
// and to whatever source asset IDs the ingestion step recorded.
func (s *Server) listDefenseCases(w http.ResponseWriter, r *http.Request) {
	if !s.defenseMode(w) {
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	rows, err := pg.QueryContext(r.Context(),
		`SELECT c.id,c.alert_id,c.status,c.opened_at,c.updated_at,
		        a.rule_id,a.title,a.severity,a.summary,a.event_id,a.asset_ids
		   FROM defense_cases c JOIN defense_alerts a ON a.id=c.alert_id
		  ORDER BY c.updated_at DESC,c.id DESC LIMIT $1`,
		defenseLimit(r))
	if err != nil {
		writeErr(w, 503, "case query failed")
		return
	}
	defer rows.Close()
	cases := make([]map[string]any, 0)
	for rows.Next() {
		var id, alertID, eventID int64
		var status, ruleID, title, severity, summary string
		var opened, updated time.Time
		var rawAssets []byte
		if err := rows.Scan(&id, &alertID, &status, &opened, &updated,
			&ruleID, &title, &severity, &summary, &eventID, &rawAssets); err != nil {
			writeErr(w, 503, "case scan failed")
			return
		}
		var assetIDs []int64
		if err := json.Unmarshal(rawAssets, &assetIDs); err != nil {
			writeErr(w, 503, "asset correlation decode failed")
			return
		}
		cases = append(cases, map[string]any{
			"id": id, "alert_id": alertID, "status": status, "opened_at": opened, "updated_at": updated,
			"rule_id": ruleID, "title": title, "severity": severity, "summary": summary,
			"event_id": eventID, "asset_ids": assetIDs, "mitre_technique": defense.Technique(ruleID),
		})
	}
	if err := rows.Err(); err != nil {
		writeErr(w, 503, "case iterator failed")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"cases": cases})
}

// POST /api/defense/cases/{id}/triage {status,reason}.
func (s *Server) triageDefenseCase(w http.ResponseWriter, r *http.Request) {
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
		Status string `json:"status"`
		Reason string `json:"reason"`
	}
	if !decodeDefenseWorkflow(w, r, &input) {
		return
	}
	reason, ok := workflowReason(w, input.Reason)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	tx, err := pg.BeginTx(ctx, nil)
	if err != nil {
		writeErr(w, 503, "case database unavailable")
		return
	}
	defer tx.Rollback()
	var current string
	err = tx.QueryRowContext(ctx, `SELECT status FROM defense_cases WHERE id=$1 FOR UPDATE`, id).Scan(&current)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, 404, "case not found")
		return
	}
	if err != nil {
		writeErr(w, 503, "case lock failed")
		return
	}
	if !defense.CaseTransition(current, input.Status) {
		writeErr(w, 409, "invalid or repeated case transition")
		return
	}
	if input.Status == defense.CaseResolved || input.Status == defense.CaseDismissed {
		var unresolved int
		err = tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM defense_response_requests
			  WHERE case_id=$1 AND status IN ('pending','approved')`, id).Scan(&unresolved)
		if err != nil {
			writeErr(w, 503, "response check failed")
			return
		}
		if unresolved != 0 {
			writeErr(w, 409, "resolve pending approvals or simulate approved plans before closing this case")
			return
		}
	}
	_, err = tx.ExecContext(ctx,
		`UPDATE defense_cases SET status=$2,updated_at=now(),
		   closed_at=CASE WHEN $2 IN ('resolved','dismissed') THEN now() ELSE NULL END
		  WHERE id=$1`, id, input.Status)
	if err != nil {
		writeErr(w, 503, "case update failed")
		return
	}
	if err := auditDefenseCase(ctx, tx, id, nil, "case_triaged",
		fmt.Sprintf("%s -> %s: %s", current, input.Status, reason)); err != nil {
		writeErr(w, 503, "case audit failed")
		return
	}
	if err := tx.Commit(); err != nil {
		writeErr(w, 503, "case commit failed")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"id": id, "status": input.Status, "executed": false})
}

// GET /api/defense/playbooks: operator-visible fixed plans only.
func (s *Server) listDefensePlaybooks(w http.ResponseWriter, r *http.Request) {
	if !s.defenseMode(w) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"playbooks": defense.Playbooks(), "execution_supported": false})
}

// POST /api/defense/cases/{id}/responses {playbook,justification}.
func (s *Server) proposeDefenseResponse(w http.ResponseWriter, r *http.Request) {
	if !s.defenseMode(w) {
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	caseID, ok := workflowID(w, r)
	if !ok {
		return
	}
	var input struct {
		Playbook      string `json:"playbook"`
		Justification string `json:"justification"`
	}
	if !decodeDefenseWorkflow(w, r, &input) {
		return
	}
	if _, exists := defense.LookupPlaybook(input.Playbook); !exists {
		writeErr(w, 400, "unknown or unreviewed response playbook")
		return
	}
	reason, ok := workflowReason(w, input.Justification)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	tx, err := pg.BeginTx(ctx, nil)
	if err != nil {
		writeErr(w, 503, "response database unavailable")
		return
	}
	defer tx.Rollback()
	var caseStatus string
	err = tx.QueryRowContext(ctx,
		`SELECT status FROM defense_cases WHERE id=$1 FOR UPDATE`, caseID).Scan(&caseStatus)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, 404, "case not found")
		return
	}
	if err != nil {
		writeErr(w, 503, "case lookup failed")
		return
	}
	if !defense.ActiveCase(caseStatus) {
		writeErr(w, 409, "response proposals require an open or investigating case")
		return
	}
	var responseID int64
	err = tx.QueryRowContext(ctx,
		`INSERT INTO defense_response_requests(case_id,playbook,justification)
		 VALUES ($1,$2,$3) RETURNING id`,
		caseID, input.Playbook, reason).Scan(&responseID)
	if err != nil {
		writeErr(w, 503, "response proposal failed")
		return
	}
	if err := auditDefenseCase(ctx, tx, caseID, &responseID,
		"response_proposed", fmt.Sprintf("%s: %s", input.Playbook, reason)); err != nil {
		writeErr(w, 503, "proposal audit failed")
		return
	}
	if err := tx.Commit(); err != nil {
		writeErr(w, 503, "response commit failed")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": responseID, "case_id": caseID, "status": defense.ResponsePending,
		"execution_supported": false,
	})
}

// GET /api/defense/responses: bounded operator approval queue.
func (s *Server) listDefenseResponses(w http.ResponseWriter, r *http.Request) {
	if !s.defenseMode(w) {
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	rows, err := pg.QueryContext(r.Context(),
		`SELECT p.id,p.case_id,c.alert_id,p.playbook,p.justification,p.status,
		        p.decision_reason,p.created_at,p.decided_at,p.simulated_at,c.status
		   FROM defense_response_requests p
		   JOIN defense_cases c ON c.id=p.case_id
		  ORDER BY p.created_at DESC,p.id DESC LIMIT $1`,
		defenseLimit(r))
	if err != nil {
		writeErr(w, 503, "response query failed")
		return
	}
	defer rows.Close()
	responses := make([]map[string]any, 0)
	for rows.Next() {
		var id, caseID, alertID int64
		var playbook, justification, status, decisionReason, caseStatus string
		var created time.Time
		var decided, simulated sql.NullTime
		if err := rows.Scan(&id, &caseID, &alertID, &playbook, &justification, &status,
			&decisionReason, &created, &decided, &simulated, &caseStatus); err != nil {
			writeErr(w, 503, "response scan failed")
			return
		}
		row := map[string]any{
			"id": id, "case_id": caseID, "alert_id": alertID,
			"playbook": playbook, "justification": justification, "status": status,
			"decision_reason": decisionReason, "created_at": created, "case_status": caseStatus,
		}
		if decided.Valid {
			row["decided_at"] = decided.Time
		}
		if simulated.Valid {
			row["simulated_at"] = simulated.Time
		}
		responses = append(responses, row)
	}
	if err := rows.Err(); err != nil {
		writeErr(w, 503, "response iterator failed")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"responses": responses})
}

// responseLockOrder pins the parent case first for all writers; this avoids
// deadlocks with triage while keeping concurrent approvals deterministic.
func responseLockOrder(ctx context.Context, tx *sql.Tx, responseID int64) (caseID int64, caseStatus, responseStatus, playbook string, err error) {
	err = tx.QueryRowContext(ctx,
		`SELECT case_id FROM defense_response_requests WHERE id=$1`, responseID).Scan(&caseID)
	if err != nil {
		return
	}
	err = tx.QueryRowContext(ctx,
		`SELECT status FROM defense_cases WHERE id=$1 FOR UPDATE`, caseID).Scan(&caseStatus)
	if err != nil {
		return
	}
	err = tx.QueryRowContext(ctx,
		`SELECT status,playbook FROM defense_response_requests
		  WHERE id=$1 AND case_id=$2 FOR UPDATE`, responseID, caseID).Scan(&responseStatus, &playbook)
	return
}

// POST /api/defense/responses/{id}/decision {decision,reason}.
// Approving records an operator authorization ONLY; no executor exists.
func (s *Server) decideDefenseResponse(w http.ResponseWriter, r *http.Request) {
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
		Decision string `json:"decision"`
		Reason   string `json:"reason"`
	}
	if !decodeDefenseWorkflow(w, r, &input) {
		return
	}
	var target, auditType string
	switch input.Decision {
	case "approve":
		target, auditType = defense.ResponseApproved, "response_approved"
	case "reject":
		target, auditType = defense.ResponseRejected, "response_rejected"
	default:
		writeErr(w, 400, "decision must be approve or reject")
		return
	}
	reason, ok := workflowReason(w, input.Reason)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	tx, err := pg.BeginTx(ctx, nil)
	if err != nil {
		writeErr(w, 503, "response database unavailable")
		return
	}
	defer tx.Rollback()
	caseID, caseStatus, current, _, err := responseLockOrder(ctx, tx, id)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, 404, "response not found")
		return
	}
	if err != nil {
		writeErr(w, 503, "response lock failed")
		return
	}
	if !defense.ActiveCase(caseStatus) || !defense.ResponseTransition(current, target) {
		writeErr(w, 409, "response decision conflicts with its current state or a closed case")
		return
	}
	_, err = tx.ExecContext(ctx,
		`UPDATE defense_response_requests
		    SET status=$2,decision_reason=$3,decided_at=now()
		  WHERE id=$1`, id, target, reason)
	if err != nil {
		writeErr(w, 503, "decision update failed")
		return
	}
	if err := auditDefenseCase(ctx, tx, caseID, &id, auditType, reason); err != nil {
		writeErr(w, 503, "decision audit failed")
		return
	}
	if err := tx.Commit(); err != nil {
		writeErr(w, 503, "decision commit failed")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"id": id, "case_id": caseID, "status": target, "executed": false})
}

// POST /api/defense/responses/{id}/simulate creates a recorded dry-run,
// never dispatching side effects. An approved response is NOT executed.
func (s *Server) simulateDefenseResponse(w http.ResponseWriter, r *http.Request) {
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
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	tx, err := pg.BeginTx(ctx, nil)
	if err != nil {
		writeErr(w, 503, "response database unavailable")
		return
	}
	defer tx.Rollback()
	caseID, caseStatus, current, playbookID, err := responseLockOrder(ctx, tx, id)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, 404, "response not found")
		return
	}
	if err != nil {
		writeErr(w, 503, "response lock failed")
		return
	}
	if !defense.ActiveCase(caseStatus) || !defense.ResponseTransition(current, defense.ResponseSimulated) {
		writeErr(w, 409, "simulation requires a previously approved plan on an active case")
		return
	}
	playbook, exists := defense.LookupPlaybook(playbookID)
	if !exists {
		writeErr(w, 409, "the referenced playbook is no longer approved")
		return
	}
	_, err = tx.ExecContext(ctx,
		`UPDATE defense_response_requests SET status='simulated',simulated_at=now() WHERE id=$1`, id)
	if err != nil {
		writeErr(w, 503, "simulation update failed")
		return
	}
	if err := auditDefenseCase(ctx, tx, caseID, &id,
		"response_simulated", "Dry-run preview produced; no external operation was executed"); err != nil {
		writeErr(w, 503, "simulation audit failed")
		return
	}
	if err := tx.Commit(); err != nil {
		writeErr(w, 503, "simulation commit failed")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{
		"id": id, "case_id": caseID, "status": defense.ResponseSimulated,
		"playbook": playbook, "executed": false,
		"warning": "Advisory only. No remote action was taken. External change control and independent safety approval are required.",
	})
}

// GET /api/defense/cases/{id}/audit. Returns the append-only decision trail.
func (s *Server) listDefenseCaseAudit(w http.ResponseWriter, r *http.Request) {
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
	rows, err := pg.QueryContext(r.Context(),
		`SELECT id,COALESCE(response_id,0),event_type,actor,reason,occurred_at
		   FROM defense_case_audit WHERE case_id=$1
		  ORDER BY occurred_at DESC,id DESC LIMIT 100`, id)
	if err != nil {
		writeErr(w, 503, "case audit unavailable")
		return
	}
	defer rows.Close()
	trail := make([]map[string]any, 0)
	for rows.Next() {
		var auditID, responseID int64
		var kind, actor, reason string
		var at time.Time
		if err := rows.Scan(&auditID, &responseID, &kind, &actor, &reason, &at); err != nil {
			writeErr(w, 503, "audit scan failed")
			return
		}
		trail = append(trail, map[string]any{
			"id": auditID, "response_id": responseID, "event_type": kind,
			"actor": actor, "reason": reason, "occurred_at": at,
		})
	}
	if err := rows.Err(); err != nil {
		writeErr(w, 503, "audit iterator failed")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"case_id": id, "audit": trail})
}

package server

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/Autumn-27/artex/defense"
)

func (s *Server) investigationControl(w http.ResponseWriter, r *http.Request) {
	if !s.defenseMode(w) {
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var auto, paused bool
	if err := pg.QueryRowContext(r.Context(),
		`SELECT auto_intake,paused FROM defense_investigation_control WHERE id=1`).
		Scan(&auto, &paused); err != nil {
		writeErr(w, 503, "investigation control unavailable")
		return
	}
	var pending, running, finished int
	if err := pg.QueryRowContext(r.Context(), `
		SELECT COUNT(*) FILTER (WHERE status='queued'),
		       COUNT(*) FILTER (WHERE status='running'),
		       COUNT(*) FILTER (WHERE status IN ('completed','failed','cancelled'))
		  FROM defense_investigation_runs`).
		Scan(&pending, &running, &finished); err != nil {
		writeErr(w, 503, "investigation statistics unavailable")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{
		"auto_intake": auto, "paused": paused,
		"queued": pending, "running": running, "finished": finished,
		"engine": "deterministic-v1", "actions_enabled": false,
		"automatic_containment": false,
		"auto_intake_max_per_hour": investigationAutoMaxHour,
		"note": "Auto-intake is opt-in; it opens high/critical alert cases only. Pausing stops new analysis, not an already-running SQL transaction. It never arms containment.",
	})
}

// POST /api/defense/investigations/control is a human-only change that
// persists across restarts and is independently audited. It cannot grant
// any agent tools or modify emergency control tables.
func (s *Server) setInvestigationControl(w http.ResponseWriter, r *http.Request) {
	if !s.defenseMode(w) {
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var input struct {
		AutoIntake *bool  `json:"auto_intake"`
		Paused     *bool  `json:"paused"`
		Reason     string `json:"reason"`
	}
	if !decodeDefenseWorkflow(w, r, &input) {
		return
	}
	reason, ok := workflowReason(w, input.Reason)
	if !ok {
		return
	}
	if input.AutoIntake == nil && input.Paused == nil {
		writeErr(w, 400, "auto_intake or paused must be supplied")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	tx, err := pg.BeginTx(ctx, nil)
	if err != nil {
		writeErr(w, 503, "investigation control unavailable")
		return
	}
	defer tx.Rollback()
	var auto, paused bool
	if err := tx.QueryRowContext(ctx, `
		UPDATE defense_investigation_control
		   SET auto_intake=COALESCE($1,auto_intake),
		       paused=COALESCE($2,paused),updated_at=now()
		 WHERE id=1 RETURNING auto_intake,paused`, input.AutoIntake, input.Paused).
		Scan(&auto, &paused); err != nil {
		writeErr(w, 503, "investigation control update failed")
		return
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO defense_investigation_control_audit
		(auto_intake,paused,reason) VALUES($1,$2,$3)`, auto, paused, reason); err != nil {
		writeErr(w, 503, "investigation control audit failed")
		return
	}
	if err := tx.Commit(); err != nil {
		writeErr(w, 503, "investigation control commit failed")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{
		"auto_intake": auto, "paused": paused, "execution": false,
	})
}

// POST /api/defense/cases/{id}/investigations: rerun or backfill a case.
// Only one queued/running investigation can exist for a case at once.
func (s *Server) queueDefenseInvestigation(w http.ResponseWriter, r *http.Request) {
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
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	tx, err := pg.BeginTx(ctx, nil)
	if err != nil {
		writeErr(w, 503, "investigation database unavailable")
		return
	}
	defer tx.Rollback()
	var status string
	err = tx.QueryRowContext(ctx,
		`SELECT status FROM defense_cases WHERE id=$1 FOR UPDATE`, caseID).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, 404, "case not found")
		return
	}
	if err != nil {
		writeErr(w, 503, "case lookup failed")
		return
	}
	if !defense.ActiveCase(status) {
		writeErr(w, 409, "investigation requires an open or investigating case")
		return
	}
	runID, created, err := enqueueDefenseInvestigation(ctx, tx, caseID, "operator")
	if err != nil {
		writeErr(w, 503, "investigation queue failed")
		return
	}
	if !created {
		writeErr(w, 409, "an investigation is already queued or running")
		return
	}
	if err := tx.Commit(); err != nil {
		writeErr(w, 503, "investigation queue commit failed")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"run_id": runID, "case_id": caseID, "queued": true, "execution": false})
}

func (s *Server) cancelDefenseInvestigation(w http.ResponseWriter, r *http.Request) {
	if !s.defenseMode(w) {
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	runID, ok := workflowID(w, r)
	if !ok {
		return
	}
	var input struct {
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
		writeErr(w, 503, "investigation database unavailable")
		return
	}
	defer tx.Rollback()
	var caseID int64
	var status string
	err = tx.QueryRowContext(ctx, `
		SELECT case_id,status FROM defense_investigation_runs
		WHERE id=$1 FOR UPDATE`, runID).Scan(&caseID, &status)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, 404, "investigation not found")
		return
	}
	if err != nil {
		writeErr(w, 503, "investigation lookup failed")
		return
	}
	if status != "queued" && status != "running" {
		writeErr(w, 409, "investigation already terminal")
		return
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE defense_investigation_runs
		  SET status='cancelled',lease_until=NULL,completed_at=now()
		WHERE id=$1`, runID); err != nil {
		writeErr(w, 503, "investigation cancellation failed")
		return
	}
	if err := appendInvestigationAudit(ctx, tx, runID, caseID, "cancelled", "console-admin", reason); err != nil {
		writeErr(w, 503, "investigation audit failed")
		return
	}
	if err := tx.Commit(); err != nil {
		writeErr(w, 503, "cancellation commit failed")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"run_id": runID, "cancelled": true, "execution": false})
}

func (s *Server) listDefenseInvestigations(w http.ResponseWriter, r *http.Request) {
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
		SELECT id,trigger_kind,status,attempts,summary,last_error,
		       created_at,started_at,completed_at
		FROM defense_investigation_runs WHERE case_id=$1 ORDER BY id DESC LIMIT 20`, id)
	if err != nil {
		writeErr(w, 503, "investigation list unavailable")
		return
	}
	runs := make([]map[string]any, 0)
	for rows.Next() {
		var runID int64
		var trigger, status, summary, lastErr string
		var attempts int
		var created time.Time
		var started, completed sql.NullTime
		if err := rows.Scan(&runID, &trigger, &status, &attempts, &summary, &lastErr,
			&created, &started, &completed); err != nil {
			rows.Close()
			writeErr(w, 503, "investigation list scan failed")
			return
		}
		runs = append(runs, map[string]any{
			"id": runID, "trigger": trigger, "status": status, "attempts": attempts,
			"summary": summary, "last_error": lastErr, "created_at": created,
			"started_at": nullableInvestigationTime(started),
			"completed_at": nullableInvestigationTime(completed),
		})
	}
	scanErr := rows.Err()
	rows.Close()
	if scanErr != nil {
		writeErr(w, 503, "investigation list iterator failed")
		return
	}
	rows, err = pg.QueryContext(r.Context(), `
		SELECT f.id,f.run_id,f.category,f.title,f.explanation,f.confidence,
		       f.evidence_event_id,f.created_at,
		       COALESCE(rv.verdict,''),COALESCE(rv.reason,''),rv.reviewed_at
		  FROM defense_investigation_findings f
		  LEFT JOIN defense_investigation_reviews rv ON rv.finding_id=f.id
		  WHERE f.case_id=$1 ORDER BY f.id DESC LIMIT 120`, id)
	if err != nil {
		writeErr(w, 503, "investigation findings unavailable")
		return
	}
	findings := make([]map[string]any, 0)
	for rows.Next() {
		var findingID, runID, eventID int64
		var category, title, explanation, verdict, reason string
		var confidence int
		var created time.Time
		var reviewed sql.NullTime
		if err := rows.Scan(&findingID, &runID, &category, &title, &explanation,
			&confidence, &eventID, &created, &verdict, &reason, &reviewed); err != nil {
			rows.Close()
			writeErr(w, 503, "finding scan failed")
			return
		}
		findings = append(findings, map[string]any{
			"id": findingID, "run_id": runID, "category": category,
			"title": title, "explanation": explanation, "confidence": confidence,
			"evidence_event_id": eventID, "created_at": created,
			"review_verdict": verdict, "review_reason": reason,
			"reviewed_at": nullableInvestigationTime(reviewed),
		})
	}
	scanErr = rows.Err()
	rows.Close()
	if scanErr != nil {
		writeErr(w, 503, "finding iterator failed")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{
		"case_id": id, "runs": runs, "findings": findings,
		"note": "Autonomous findings are evidence-backed suggestions, NOT verified attacker attribution or response approvals.",
	})
}

func nullableInvestigationTime(t sql.NullTime) any {
	if t.Valid {
		return t.Time
	}
	return nil
}

func (s *Server) reviewDefenseFinding(w http.ResponseWriter, r *http.Request) {
	if !s.defenseMode(w) {
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	findingID, ok := workflowID(w, r)
	if !ok {
		return
	}
	var input struct {
		Verdict string `json:"verdict"`
		Reason  string `json:"reason"`
	}
	if !decodeDefenseWorkflow(w, r, &input) {
		return
	}
	reason, ok := workflowReason(w, input.Reason)
	if !ok {
		return
	}
	switch input.Verdict {
	case "supported", "refuted", "needs_more_evidence":
	default:
		writeErr(w, 400, "invalid review verdict")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	tx, err := pg.BeginTx(ctx, nil)
	if err != nil {
		writeErr(w, 503, "finding review database unavailable")
		return
	}
	defer tx.Rollback()
	var caseID, runID int64
	err = tx.QueryRowContext(ctx, `
		SELECT f.case_id,f.run_id FROM defense_investigation_findings f
		WHERE f.id=$1 FOR SHARE`, findingID).Scan(&caseID, &runID)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, 404, "finding not found")
		return
	}
	if err != nil {
		writeErr(w, 503, "finding lookup failed")
		return
	}
	var reviewID int64
	err = tx.QueryRowContext(ctx, `
		INSERT INTO defense_investigation_reviews
		(finding_id,case_id,verdict,reason)
		VALUES($1,$2,$3,$4)
		ON CONFLICT(finding_id) DO NOTHING RETURNING id`,
		findingID, caseID, input.Verdict, reason).Scan(&reviewID)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, 409, "finding already reviewed; original verdict is immutable")
		return
	}
	if err != nil {
		writeErr(w, 503, "finding review failed")
		return
	}
	detail := fmt.Sprintf("Reviewed finding #%d as %s; review #%d contains rationale", findingID, input.Verdict, reviewID)
	if err := appendInvestigationAudit(ctx, tx, runID, caseID, "reviewed", "console-admin", detail); err != nil {
		writeErr(w, 503, "finding audit failed")
		return
	}
	if err := tx.Commit(); err != nil {
		writeErr(w, 503, "review commit failed")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{
		"review_id": reviewID, "finding_id": findingID,
		"verdict": input.Verdict, "execution": false,
	})
}

// This helper intentionally accepts positive decimal IDs only. The server
// passes all review IDs through the existing workflowID path gate.
func investigationID(raw string) (int64, bool) {
	id, err := strconv.ParseInt(raw, 10, 64)
	return id, err == nil && id > 0
}

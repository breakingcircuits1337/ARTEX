package server

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"time"
)

// revertEmergencyAction is a guarded single-IP reversal, never an arbitrary
// network command. Successful manual reversal prevents re-blocking for 30m.
func (s *Server) revertEmergencyAction(id int64) error {
	ctx, cancel := context.WithTimeout(s.ctx, 3*time.Second)
	defer cancel()
	tx, err := s.m.pg.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Serialize with new admissions to avoid an immediate re-block between
	// the kernel removal and the per-source suppression commit.
	if _, err := tx.ExecContext(ctx,
		"SELECT pg_advisory_xact_lock($1)", emergencyQueueLock); err != nil {
		return err
	}
	var source, backend, status string
	err = tx.QueryRowContext(ctx, `
		SELECT source_ip,backend,status
		  FROM defense_emergency_actions WHERE id=$1 FOR UPDATE`, id).
		Scan(&source, &backend, &status)
	if err != nil {
		return err
	}
	if status == "reverted" || status == "expired" {
		return errors.New("action is already reverted or expired")
	}
	if status != "pending" && status != "active" &&
		status != "simulated" && status != "failed" {
		return errors.New("action cannot be reversed")
	}
	if backend == "nftables" {
		if err := (nftEmergencyBackend{}).Revert(ctx, source); err != nil {
			auditErr := appendEmergencyAudit(ctx, tx, &id, "revert_failed", "console-admin",
				"Operator requested one-click reversal; kernel removal was not confirmed")
			if auditErr == nil {
				_ = tx.Commit() // preserve failed attempt without claiming reversal
			}
			return errors.New("kernel removal could not be confirmed")
		}
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO defense_emergency_suppressions(source_ip,suppress_until)
		VALUES($1,now()+interval '30 minutes')
		ON CONFLICT(source_ip) DO UPDATE
		SET suppress_until=excluded.suppress_until,updated_at=now()`, source); err != nil {
		return err
	}
	if err := updateEmergencyState(ctx, tx, id, "reverted",
		"Operator one-click reversal; automatic re-block suppressed for 30 minutes",
		"console-admin", "reversed", 0); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Server) emergencyRevertOne(w http.ResponseWriter, r *http.Request) {
	if !s.defenseMode(w) {
		return
	}
	if s.pg(w) == nil {
		return
	}
	id, ok := workflowID(w, r)
	if !ok {
		return
	}
	if err := s.revertEmergencyAction(id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, 404, "action not found")
		} else {
			writeErr(w, 409, "reversal not confirmed: "+err.Error())
		}
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{
		"id": id, "status": "reverted",
		"operator_requested": true, "rearm_suppressed_minutes": 30,
	})
}

// Panic stop: pause first, then walk every potentially active/uncertain
// action. It returns partial failures explicitly, never promises total
// restoration when the kernel adapter cannot confirm a reversal.
func (s *Server) emergencyRevertAll(w http.ResponseWriter, r *http.Request) {
	if !s.defenseMode(w) {
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	if err := updateEmergencyControl(ctx, pg, true); err != nil {
		cancel()
		writeErr(w, 503, "emergency stop could not pause new actions")
		return
	}
	cancel()
	rows, err := pg.QueryContext(r.Context(), `
		SELECT id FROM defense_emergency_actions
		 WHERE status IN ('active','pending','failed','simulated')
		 ORDER BY CASE status
		   WHEN 'active' THEN 0 WHEN 'pending' THEN 1
		   WHEN 'failed' THEN 2 ELSE 3 END, id
		 LIMIT 200`)
	if err != nil {
		writeErr(w, 503, "emergency ledger unavailable")
		return
	}
	ids := make([]int64, 0)
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			writeErr(w, 503, "emergency action list failed")
			return
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		writeErr(w, 503, "emergency action list failed")
		return
	}
	rows.Close()
	reversed, failed := 0, 0
	for _, id := range ids {
		if err := s.revertEmergencyAction(id); err == nil {
			reversed++
		} else {
			failed++
		}
	}
	var remaining int
	if err := pg.QueryRowContext(r.Context(), `
		SELECT count(*) FROM defense_emergency_actions
		 WHERE status IN ('active','pending','failed','simulated')`).Scan(&remaining); err != nil {
		writeErr(w, 503, "could not confirm remaining emergency actions")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	code := 200
	if failed > 0 || remaining > 0 {
		code = http.StatusMultiStatus
	}
	writeJSON(w, code, map[string]any{
		"paused": true, "reverted": reversed, "failed": failed,
		"remaining": remaining,
		"warning": "Any failed or remaining action requires operator verification on the dedicated kernel set",
	})
}

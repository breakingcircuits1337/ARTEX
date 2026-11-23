package server

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/defense"
)

// Emergency endpoints inherit ARTEX's JWT and cookie CSRF protection.
// The operator pre-authorizes automatic action by arming this bounded policy.
func (s *Server) emergencyStatus(w http.ResponseWriter, r *http.Request) {
	if !s.defenseMode(w) {
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	cfg, configErr := defense.LoadEmergencyConfig()
	if configErr != nil {
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, 200, map[string]any{
			"mode": "invalid", "armed": false, "backend_ready": false,
			"error": configErr.Error(),
		})
		return
	}
	var paused bool
	if err := pg.QueryRowContext(r.Context(),
		"SELECT paused FROM defense_emergency_control WHERE id=1").Scan(&paused); err != nil {
		writeErr(w, 503, "emergency control unavailable")
		return
	}
	ready := cfg.Mode == defense.EmergencySimulate
	if cfg.Mode == defense.EmergencyNFT {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second)
		defer cancel()
		ready = (nftEmergencyBackend{}).Check(ctx) == nil
	}
	var active, total int64
	if err := pg.QueryRowContext(r.Context(), `
		SELECT COUNT(*) FILTER (WHERE status IN ('pending','active','failed')),
		       COUNT(*) FROM defense_emergency_actions`).Scan(&active, &total); err != nil {
		writeErr(w, 503, "emergency ledger unavailable")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{
		"mode": cfg.Mode, "armed": !paused && cfg.Mode != defense.EmergencyOff && ready,
		"paused": paused, "backend_ready": ready,
		"protected_cidrs": len(cfg.Protected), "ttl_seconds": int(cfg.TTL.Seconds()),
		"max_active": cfg.MaxActive, "max_per_hour": cfg.MaxPerHour,
		"active": active, "action_count": total,
		"description": EmergencyBackendDescription(cfg.Mode, ready),
		"live_effects": cfg.Mode == defense.EmergencyNFT,
		"warning": "Only exact-source IPv4 blocks can be reversed. Previously dropped packets or interrupted sessions cannot be restored.",
	})
}

// updateEmergencyControl is transactional with the operator's audit record.
func updateEmergencyControl(ctx context.Context, pg *db.DB, paused bool) error {
	tx, err := pg.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	reason, kind := "Operator armed narrowly scoped emergency mode from SOC", "armed"
	if paused {
		reason, kind = "Operator paused new emergency actions from SOC", "paused"
	}
	_, err = tx.ExecContext(ctx, `
		UPDATE defense_emergency_control
		 SET paused=$1,updated_at=now(),operator_reason=$2
		WHERE id=1`, paused, reason)
	if err != nil {
		return err
	}
	if err := appendEmergencyAudit(ctx, tx, nil, kind, "console-admin", reason); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Server) emergencyArm(w http.ResponseWriter, r *http.Request) {
	if !s.defenseMode(w) {
		return
	}
	cfg, err := defense.LoadEmergencyConfig()
	if err != nil || cfg.Mode == defense.EmergencyOff {
		writeErr(w, 409, "configure an allowed emergency mode and protected IPv4 CIDRs first")
		return
	}
	if cfg.Mode == defense.EmergencyNFT {
		ctx, cancel := context.WithTimeout(r.Context(), 1500*time.Millisecond)
		defer cancel()
		if err := (nftEmergencyBackend{}).Check(ctx); err != nil {
			writeErr(w, 503, "the dedicated nftables timeout set is not available")
			return
		}
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	if err := updateEmergencyControl(ctx, pg, false); err != nil {
		writeErr(w, 503, "could not arm emergency mode")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"armed": true, "mode": cfg.Mode})
}

func (s *Server) emergencyPause(w http.ResponseWriter, r *http.Request) {
	if !s.defenseMode(w) {
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	if err := updateEmergencyControl(ctx, pg, true); err != nil {
		writeErr(w, 503, "could not pause emergency mode")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{
		"paused": true,
		"note": "New actions blocked. Existing kernel entries still require one-click undo or TTL expiration.",
	})
}

func emergencyListLimit(raw string) (int, error) {
	if raw == "" {
		return 100, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > 200 {
		return 0, errors.New("limit must be 1..200")
	}
	return n, nil
}

// A cursor-paged log keeps ALL previous actions visible for retrospective
// investigation, not just those still active in the firewall.
func (s *Server) emergencyListActions(w http.ResponseWriter, r *http.Request) {
	if !s.defenseMode(w) {
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	limit, err := emergencyListLimit(r.URL.Query().Get("limit"))
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	before := int64(0)
	if raw := r.URL.Query().Get("before_id"); raw != "" {
		before, err = strconv.ParseInt(raw, 10, 64)
		if err != nil || before < 1 {
			writeErr(w, 400, "invalid before_id")
			return
		}
	}
	rows, err := pg.QueryContext(r.Context(), `
		SELECT id,event_id,source_ip,destination_ip,rule_id,explanation,backend,status,
		       created_at,applied_at,expires_at,reversed_at,latency_ms,outcome_detail
		  FROM defense_emergency_actions
		 WHERE ($1::bigint=0 OR id<$1)
		 ORDER BY id DESC LIMIT $2`, before, limit)
	if err != nil {
		writeErr(w, 503, "emergency actions unavailable")
		return
	}
	defer rows.Close()
	actions := make([]map[string]any, 0)
	next := int64(0)
	for rows.Next() {
		var id, eventID, elapsed int64
		var source, destination, rule, explanation, backend, status, detail string
		var created, expires time.Time
		var applied, reversed sql.NullTime
		if err := rows.Scan(&id, &eventID, &source, &destination, &rule,
			&explanation, &backend, &status, &created, &applied, &expires,
			&reversed, &elapsed, &detail); err != nil {
			writeErr(w, 503, "emergency action scan failed")
			return
		}
		next = id
		item := map[string]any{
			"id": id, "event_id": eventID, "source_ip": source,
			"destination_ip": destination, "rule_id": rule, "explanation": explanation,
			"backend": backend, "status": status, "created_at": created,
			"expires_at": expires, "latency_ms": elapsed, "outcome_detail": detail,
			"reversible": status == "pending" || status == "active" ||
				status == "simulated" || status == "failed",
		}
		if applied.Valid {
			item["applied_at"] = applied.Time
		}
		if reversed.Valid {
			item["reversed_at"] = reversed.Time
		}
		actions = append(actions, item)
	}
	if rows.Err() != nil {
		writeErr(w, 503, "action list interrupted")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{
		"actions": actions, "next_before_id": next,
		"has_more": len(actions) == limit,
	})
}

func (s *Server) emergencyListAudit(w http.ResponseWriter, r *http.Request) {
	if !s.defenseMode(w) {
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	limit, err := emergencyListLimit(r.URL.Query().Get("limit"))
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	rows, err := pg.QueryContext(r.Context(), `
		SELECT id,COALESCE(action_id,0),event_type,actor,detail,occurred_at
		  FROM defense_emergency_audit ORDER BY id DESC LIMIT $1`, limit)
	if err != nil {
		writeErr(w, 503, "emergency audit unavailable")
		return
	}
	defer rows.Close()
	events := make([]map[string]any, 0)
	for rows.Next() {
		var id, actionID int64
		var kind, actor, detail string
		var occurred time.Time
		if err := rows.Scan(&id, &actionID, &kind, &actor, &detail, &occurred); err != nil {
			writeErr(w, 503, "emergency audit scan failed")
			return
		}
		events = append(events, map[string]any{
			"id": id, "action_id": actionID, "event_type": kind,
			"actor": actor, "detail": detail, "occurred_at": occurred,
		})
	}
	if rows.Err() != nil {
		writeErr(w, 503, "audit iterator failed")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"audit": events})
}

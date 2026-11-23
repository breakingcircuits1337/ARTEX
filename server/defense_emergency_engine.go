package server

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/Autumn-27/artex/defense"
)

// Serialize emergency budgets across concurrent ingest requests and processes.
const emergencyQueueLock int64 = 8127726441

// stageEmergencyAction runs on the normalized event path WITHOUT an LLM. It
// persists intent atomically with the supporting event, never a kernel change.
func (s *Server) stageEmergencyAction(
	ctx context.Context, tx *sql.Tx, event defense.SecurityEvent, eventID int64, now time.Time,
) (int64, error) {
	cfg, err := defense.LoadEmergencyConfig()
	if err != nil || cfg.Mode == defense.EmergencyOff ||
		!cfg.EligibleIP(event.SrcIP, event.DstIP) {
		return 0, nil
	}
	age := now.Sub(event.ObservedAt)
	if age < -5*time.Second || age > cfg.Freshness {
		return 0, nil
	}
	possibleIDS := event.Source == "suricata" && event.Kind == "network" &&
		event.Action == "alert" && event.VendorAlert && event.Severity >= 9 &&
		event.Signature != ""
	possibleSpray := event.Source == "wazuh" && event.Kind == "authentication" &&
		event.Outcome == "failure" && event.Username != ""
	if !possibleIDS && !possibleSpray {
		return 0, nil
	}
	if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock($1)", emergencyQueueLock); err != nil {
		return 0, err
	}
	// A share lock prevents an operator pause from racing with admission.
	var paused bool
	if err := tx.QueryRowContext(ctx,
		"SELECT paused FROM defense_emergency_control WHERE id=1 FOR SHARE").Scan(&paused); err != nil {
		return 0, err
	}
	if paused {
		return 0, nil
	}
	var repeatedAlerts, accounts int
	if possibleIDS {
		err = tx.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM defense_events
			 WHERE source='suricata' AND kind='network' AND action='alert'
			   AND vendor_alert AND severity>=9
			   AND src_ip=$1 AND dst_ip=$2 AND signature=$3
			   AND observed_at BETWEEN $4 AND $5`,
			event.SrcIP, event.DstIP, event.Signature,
			event.ObservedAt.Add(-10*time.Second), event.ObservedAt,
		).Scan(&repeatedAlerts)
	} else {
		err = tx.QueryRowContext(ctx, `
			SELECT COUNT(DISTINCT lower(username)) FROM defense_events
			 WHERE source='wazuh' AND kind='authentication' AND outcome='failure'
			   AND src_ip=$1 AND dst_ip=$2 AND username<>''
			   AND observed_at BETWEEN $3 AND $4`,
			event.SrcIP, event.DstIP,
			event.ObservedAt.Add(-time.Minute), event.ObservedAt,
		).Scan(&accounts)
	}
	if err != nil {
		return 0, err
	}
	decision, eligible := cfg.Decide(event, now, repeatedAlerts, accounts)
	if !eligible {
		return 0, nil
	}
	var suppressed bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS(SELECT 1 FROM defense_emergency_suppressions
		WHERE source_ip=$1 AND suppress_until>now())`,
		event.SrcIP).Scan(&suppressed); err != nil {
		return 0, err
	}
	if suppressed {
		return 0, nil
	}
	var active, perHour int
	if err := tx.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM defense_emergency_actions
		WHERE status IN ('pending','active')`).Scan(&active); err != nil {
		return 0, err
	}
	if active >= cfg.MaxActive {
		return 0, nil
	}
	if err := tx.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM defense_emergency_actions
		WHERE created_at >= now() - interval '1 hour'`).Scan(&perHour); err != nil {
		return 0, err
	}
	if perHour >= cfg.MaxPerHour {
		return 0, nil
	}
	var actionID int64
	err = tx.QueryRowContext(ctx, `
		INSERT INTO defense_emergency_actions
			(event_id,source_ip,destination_ip,rule_id,explanation,backend,expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT DO NOTHING RETURNING id`,
		eventID, event.SrcIP, event.DstIP, decision.Rule, decision.Reason,
		string(cfg.Mode), now.Add(cfg.TTL),
	).Scan(&actionID)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if err := appendEmergencyAudit(ctx, tx, &actionID,
		"queued", "policy-engine", decision.Reason); err != nil {
		return 0, err
	}
	return actionID, nil
}

func appendEmergencyAudit(
	ctx context.Context, tx *sql.Tx, actionID *int64,
	eventType, actor, detail string,
) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO defense_emergency_audit(action_id,event_type,actor,detail)
		VALUES($1,$2,$3,$4)`, actionID, eventType, actor, detail)
	return err
}

func updateEmergencyState(
	ctx context.Context, tx *sql.Tx, id int64,
	status, detail, actor, kind string, elapsed time.Duration,
) error {
	millis := elapsed.Milliseconds()
	if millis < 0 {
		millis = 0
	}
	_, err := tx.ExecContext(ctx, `
		UPDATE defense_emergency_actions
		 SET status=$2, outcome_detail=$3, latency_ms=$4,
			 applied_at=CASE WHEN $2 IN ('active','simulated') THEN now() ELSE applied_at END,
			 reversed_at=CASE WHEN $2 IN ('reverted','expired') THEN now() ELSE reversed_at END
		 WHERE id=$1`, id, status, detail, millis)
	if err != nil {
		return err
	}
	return appendEmergencyAudit(ctx, tx, &id, kind, actor, detail)
}

// applyEmergencyAction runs immediately after commit and on reconciler ticks.
// If ARTEX crashes between the kernel and SQL updates, the kernel timeout
// eventually removes the block; rerunning adoption is idempotent.
func (s *Server) applyEmergencyAction(id int64) {
	if s.m == nil || s.m.pg == nil {
		return
	}
	ctx, cancel := context.WithTimeout(s.ctx, 3*time.Second)
	defer cancel()
	cfg, cfgErr := defense.LoadEmergencyConfig()
	tx, err := s.m.pg.BeginTx(ctx, nil)
	if err != nil {
		return
	}
	defer tx.Rollback()
	var paused bool
	if err := tx.QueryRowContext(ctx,
		"SELECT paused FROM defense_emergency_control WHERE id=1 FOR SHARE").Scan(&paused); err != nil {
		return
	}
	var source, destination, backend, status string
	var created, expires time.Time
	err = tx.QueryRowContext(ctx, `
		SELECT source_ip,destination_ip,backend,status,created_at,expires_at
		FROM defense_emergency_actions WHERE id=$1 FOR UPDATE`, id,
	).Scan(&source, &destination, &backend, &status, &created, &expires)
	if err != nil || status != "pending" {
		return
	}
	now := time.Now()
	if paused || cfgErr != nil || cfg.Mode == defense.EmergencyOff ||
		string(cfg.Mode) != backend || !cfg.EligibleIP(source, destination) {
		if err := updateEmergencyState(ctx, tx, id, "reverted",
			"Skipped before application: emergency mode paused or scope invalid",
			"policy-engine", "reversed", 0); err == nil {
			_ = tx.Commit()
		}
		return
	}
	if !expires.After(now) {
		if err := updateEmergencyState(ctx, tx, id, "expired",
			"Pending action expired without execution",
			"policy-engine", "expired", 0); err == nil {
			_ = tx.Commit()
		}
		return
	}
	if backend == "simulate" {
		if err := updateEmergencyState(ctx, tx, id, "simulated",
			"Simulation only; no firewall rule or external operation",
			"policy-engine", "simulated", 0); err == nil {
			_ = tx.Commit()
		}
		return
	}
	if backend != "nftables" {
		return
	}
	adapter := nftEmergencyBackend{}
	start := time.Now()
	var runErr error
	// A stale backlog must never create a fresh network block after an old
	// alert; however, previously applied and still-live kernel entries can
	// be reconciled safely after a restart.
	if now.Sub(created) > 15*time.Second {
		// Do not generate delayed blocks after a restart. If the gateway
		// applied before a crash, its kernel TTL remains the failsafe and
		// the operator can still undo this uncertain ledger row.
		runErr = errors.New("decision became stale before enforcement")
	} else {
		runErr = adapter.Apply(ctx, source, destination, time.Until(expires))
	}
	if runErr != nil {
		if err := updateEmergencyState(ctx, tx, id, "failed",
			"Kernel enforcement unavailable or rejected; check for an earlier side effect",
			"policy-engine", "apply_failed", time.Since(start)); err == nil {
			_ = tx.Commit()
		}
		return
	}
	if err := updateEmergencyState(ctx, tx, id, "active",
		"Exact IPv4 added to dedicated nftables timeout set",
		"policy-engine", "applied", time.Since(start)); err == nil {
		_ = tx.Commit()
	}
}

func (s *Server) expireEmergencyAction(id int64) {
	ctx, cancel := context.WithTimeout(s.ctx, 3*time.Second)
	defer cancel()
	tx, err := s.m.pg.BeginTx(ctx, nil)
	if err != nil {
		return
	}
	defer tx.Rollback()
	var source, backend, status string
	var expires time.Time
	err = tx.QueryRowContext(ctx, `
		SELECT source_ip,backend,status,expires_at
		FROM defense_emergency_actions WHERE id=$1 FOR UPDATE`, id).
		Scan(&source, &backend, &status, &expires)
	if err != nil || status != "active" || time.Now().Before(expires) {
		return
	}
	if backend == "nftables" {
		if err := (nftEmergencyBackend{}).Revert(ctx, source); err != nil {
			return
		}
	}
	if err := updateEmergencyState(ctx, tx, id, "expired",
		"Emergency TTL elapsed and kernel entry removed or absent",
		"policy-engine", "expired", 0); err == nil {
		_ = tx.Commit()
	}
}

func (s *Server) runEmergencyReconciler() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		s.reconcileEmergencyOnce()
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *Server) reconcileEmergencyOnce() {
	if s.m == nil || s.m.pg == nil {
		return
	}
	ctx, cancel := context.WithTimeout(s.ctx, 2*time.Second)
	defer cancel()
	rows, err := s.m.pg.QueryContext(ctx, `
		SELECT id,status FROM defense_emergency_actions
		 WHERE status='pending' OR (status='active' AND expires_at<=now())
		 ORDER BY id LIMIT 25`)
	if err != nil {
		return
	}
	type row struct {
		id     int64
		status string
	}
	var selected []row
	for rows.Next() {
		var rec row
		if err := rows.Scan(&rec.id, &rec.status); err != nil {
			rows.Close()
			return
		}
		selected = append(selected, rec)
	}
	rows.Close()
	if rows.Err() != nil {
		return
	}
	for _, rec := range selected {
		if rec.status == "pending" {
			s.applyEmergencyAction(rec.id)
		} else {
			s.expireEmergencyAction(rec.id)
		}
	}
}

func EmergencyBackendDescription(mode defense.EmergencyMode, ready bool) string {
	switch mode {
	case defense.EmergencyOff:
		return "Disabled: no autonomous action can run"
	case defense.EmergencySimulate:
		return "Simulation: decisions recorded without firewall changes"
	case defense.EmergencyNFT:
		if ready {
			return "Live nftables: preprovisioned kernel timeout set"
		}
		return "Not ready: nftables timeout set unavailable"
	default:
		return fmt.Sprintf("Invalid emergency mode: %s", mode)
	}
}

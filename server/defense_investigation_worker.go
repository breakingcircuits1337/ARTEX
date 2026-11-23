package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/Autumn-27/artex/defense"
)

const (
	investigationTickInterval = 2 * time.Second
	investigationLease        = 30 * time.Second
	investigationMaxAttempts  = 3
	investigationAutoMaxHour  = 30
	investigationIntakeLock   = int64(8187707701)
)

func enqueueDefenseInvestigation(ctx context.Context, tx *sql.Tx, caseID int64, trigger string) (int64, bool, error) {
	var id int64
	err := tx.QueryRowContext(ctx, `
		INSERT INTO defense_investigation_runs(case_id,trigger_kind,status)
		VALUES($1,$2,'queued') ON CONFLICT DO NOTHING RETURNING id`,
		caseID, trigger).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	actor := "console-admin"
	if trigger == "auto_alert" {
		actor = "investigator"
	}
	if err := appendInvestigationAudit(ctx, tx, id, caseID, "queued",
		actor, "Review-only investigation queued from stored case evidence"); err != nil {
		return 0, false, err
	}
	return id, true, nil
}

func appendInvestigationAudit(ctx context.Context, tx *sql.Tx, runID, caseID int64, kind, actor, detail string) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO defense_investigation_audit(run_id,case_id,event_type,actor,detail)
		VALUES($1,$2,$3,$4,$5)`, runID, caseID, kind, actor, detail)
	return err
}

// runDefenseInvestigator is a durable, polling background service. A crash
// leaves only a SQL lease, which expires and may be retried. Every action is
// bounded local database analysis: no LLM, network, scanner or containment.
func (s *Server) runDefenseInvestigator() {
	if s.m == nil || s.m.pg == nil || s.ctx == nil {
		return
	}
	ticker := time.NewTicker(investigationTickInterval)
	defer ticker.Stop()
	for {
		s.investigatorTick()
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *Server) investigatorTick() {
	if !defense.Restricted() || s.ctx.Err() != nil {
		return
	}
	ctx, cancel := context.WithTimeout(s.ctx, 16*time.Second)
	defer cancel()
	var autoIntake, paused bool
	if err := s.m.pg.QueryRowContext(ctx, `
		SELECT auto_intake,paused FROM defense_investigation_control WHERE id=1`).
		Scan(&autoIntake, &paused); err != nil {
		log.Printf("[investigator] read control: %v", err)
		return
	}
	if paused {
		return
	}
	if autoIntake {
		if err := s.intakeDefenseAlert(ctx); err != nil {
			log.Printf("[investigator] alert intake failed: %v", err)
		}
	}
	for i := 0; i < 2; i++ {
		var runID, caseID int64
		var attempt int
		err := s.m.pg.QueryRowContext(ctx, `
			WITH next AS (
			  SELECT id FROM defense_investigation_runs
			  WHERE (status='queued' OR (status='running' AND lease_until < now()))
			    AND attempts < $1
			  ORDER BY created_at,id
			  FOR UPDATE SKIP LOCKED LIMIT 1
			)
			UPDATE defense_investigation_runs r
			   SET status='running',attempts=attempts+1,
			       started_at=COALESCE(started_at,now()),
			       lease_until=now()+interval '30 seconds'
			  FROM next
			 WHERE r.id=next.id
			RETURNING r.id,r.case_id,r.attempts`, investigationMaxAttempts).
			Scan(&runID, &caseID, &attempt)
		if errors.Is(err, sql.ErrNoRows) {
			break
		}
		if err != nil {
			log.Printf("[investigator] acquire run: %v", err)
			return
		}
		if err := s.executeDefenseInvestigation(ctx, runID, caseID, attempt); err != nil {
			log.Printf("[investigator] run %d failed: %v", runID, err)
			s.retryDefenseInvestigation(runID, caseID, attempt)
		}
	}
	// Only exhausted abandoned leases can become failed. No duplicate run
	// launches or infinite retry loops after repeated process crashes.
	if _, err := s.m.pg.ExecContext(ctx, `
		WITH expired AS (
		  UPDATE defense_investigation_runs
		     SET status='failed',last_error='Lease expired after maximum retries',
		         completed_at=now(),lease_until=NULL
		   WHERE status='running' AND attempts >= $1 AND lease_until < now()
		   RETURNING id,case_id
		)
		INSERT INTO defense_investigation_audit
		  (run_id,case_id,event_type,actor,detail)
		SELECT id,case_id,'failed','investigator',
		       'Lease expired after maximum retries; no external actions performed'
		FROM expired`, investigationMaxAttempts); err != nil {
		log.Printf("[investigator] stale lease reconcile: %v", err)
	}
}

// intakeDefenseAlert admits at most one new high/critical case per tick, with
// a global advisory lock and an hourly quota across all server instances.
// It only creates an investigation case and NEVER approves a response action.
func (s *Server) intakeDefenseAlert(ctx context.Context) error {
	tx, err := s.m.pg.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, investigationIntakeLock); err != nil {
		return err
	}
	var auto, paused bool
	if err := tx.QueryRowContext(ctx,
		`SELECT auto_intake,paused FROM defense_investigation_control WHERE id=1 FOR SHARE`).
		Scan(&auto, &paused); err != nil {
		return err
	}
	if !auto || paused {
		return tx.Commit()
	}
	var count int
	if err := tx.QueryRowContext(ctx, `
		SELECT count(*) FROM defense_investigation_runs
		WHERE trigger_kind='auto_alert' AND created_at>=now()-interval '1 hour'`).Scan(&count); err != nil {
		return err
	}
	if count >= investigationAutoMaxHour {
		return tx.Commit()
	}
	var alertID int64
	err = tx.QueryRowContext(ctx, `
		SELECT a.id FROM defense_alerts a
		WHERE a.severity IN ('high','critical')
		  AND a.created_at >= now()-interval '24 hours'
		  AND NOT EXISTS(SELECT 1 FROM defense_cases c WHERE c.alert_id=a.id)
		ORDER BY a.created_at,a.id
		FOR UPDATE OF a SKIP LOCKED LIMIT 1`).Scan(&alertID)
	if errors.Is(err, sql.ErrNoRows) {
		return tx.Commit()
	}
	if err != nil {
		return err
	}
	var caseID int64
	err = tx.QueryRowContext(ctx, `
		INSERT INTO defense_cases(alert_id) VALUES($1)
		ON CONFLICT(alert_id) DO NOTHING RETURNING id`, alertID).Scan(&caseID)
	if errors.Is(err, sql.ErrNoRows) {
		return tx.Commit()
	}
	if err != nil {
		return err
	}
	if err := auditDefenseCase(ctx, tx, caseID, nil, "case_opened",
		"Automatic evidence-only intake of high/critical alert; human verification required"); err != nil {
		return err
	}
	if _, err := correlateDefenseCase(ctx, tx, caseID, "correlator"); err != nil {
		return err
	}
	if _, created, err := enqueueDefenseInvestigation(ctx, tx, caseID, "auto_alert"); err != nil {
		return err
	} else if !created {
		return errors.New("auto-intake case missing investigation queue entry")
	}
	return tx.Commit()
}

// Collect read-only evidence within a transaction. Inserting derived findings
// is guarded by the same run row lock used by cancellation and review.
func (s *Server) executeDefenseInvestigation(ctx context.Context, runID, caseID int64, attempt int) error {
	tx, err := s.m.pg.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var status, caseStatus string
	var recordedAttempt int
	if err := tx.QueryRowContext(ctx, `
		SELECT status,attempts FROM defense_investigation_runs
		WHERE id=$1 AND case_id=$2 FOR UPDATE`, runID, caseID).Scan(&status, &recordedAttempt); err != nil {
		return err
	}
	if status != "running" || recordedAttempt != attempt {
		return nil // cancelled, superseded or already completed
	}
	if err := tx.QueryRowContext(ctx, `SELECT status FROM defense_cases WHERE id=$1`, caseID).
		Scan(&caseStatus); err != nil {
		return err
	}
	if !defense.ActiveCase(caseStatus) {
		if _, err := tx.ExecContext(ctx, `
			UPDATE defense_investigation_runs
			 SET status='cancelled',completed_at=now(),lease_until=NULL
			 WHERE id=$1`, runID); err != nil {
			return err
		}
		if err := appendInvestigationAudit(ctx, tx, runID, caseID, "cancelled",
			"investigator", "Source case was already terminal; no findings created"); err != nil {
			return err
		}
		return tx.Commit()
	}
	if err := appendInvestigationAudit(ctx, tx, runID, caseID, "started",
		"investigator", "Bounded local investigation started; no active tools available"); err != nil {
		return err
	}
	// Refresh correlations while holding the run lock. Case graph rows and
	// derived findings commit together to prevent misleading partial results.
	if _, err := correlateDefenseCase(ctx, tx, caseID, ""); err != nil {
		return err
	}
	var snapshot defense.InvestigationSnapshot
	var rawAssetIDs []byte
	if err := tx.QueryRowContext(ctx, `
		SELECT a.event_id,a.rule_id,a.severity,a.asset_ids
		  FROM defense_cases c JOIN defense_alerts a ON a.id=c.alert_id
		 WHERE c.id=$1`, caseID).
		Scan(&snapshot.AnchorEventID, &snapshot.RuleID, &snapshot.AlertSeverity, &rawAssetIDs); err != nil {
		return err
	}
	if err := json.Unmarshal(rawAssetIDs, &snapshot.AssetIDs); err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT o.event_id,e.source,o.link_reason,o.linkage_confidence
		FROM defense_case_observations o
		JOIN defense_events e ON e.id=o.event_id
		WHERE o.case_id=$1 ORDER BY e.observed_at DESC,e.id DESC LIMIT 50`, caseID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var o defense.InvestigationObservation
		if err := rows.Scan(&o.EventID, &o.Source, &o.LinkReason, &o.LinkConfidence); err != nil {
			rows.Close()
			return err
		}
		snapshot.Observations = append(snapshot.Observations, o)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	rows, err = tx.QueryContext(ctx, `
		SELECT evidence_event_id,technique_id,confidence,mapping_source
		FROM defense_case_techniques WHERE case_id=$1 ORDER BY id DESC LIMIT 20`, caseID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var m defense.InvestigationTechnique
		if err := rows.Scan(&m.EventID, &m.Technique, &m.Confidence, &m.Origin); err != nil {
			rows.Close()
			return err
		}
		snapshot.Techniques = append(snapshot.Techniques, m)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	findings := defense.AnalyzeInvestigation(snapshot)
	for _, f := range findings {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO defense_investigation_findings
			 (run_id,case_id,category,title,explanation,confidence,evidence_event_id)
			VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`,
			runID, caseID, f.Category, f.Title, f.Explanation, f.Confidence, f.EvidenceEventID); err != nil {
			return err
		}
	}
	summary := fmt.Sprintf("%d bounded, evidence-linked review findings; unverified until operator review; no response executed", len(findings))
	if _, err := tx.ExecContext(ctx, `
		UPDATE defense_investigation_runs SET status='completed',summary=$2,
		       completed_at=now(),lease_until=NULL,last_error=''
		 WHERE id=$1`, runID, summary); err != nil {
		return err
	}
	if err := appendInvestigationAudit(ctx, tx, runID, caseID, "completed",
		"investigator", summary); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Server) retryDefenseInvestigation(runID, caseID int64, attempt int) {
	if s.ctx.Err() != nil {
		return
	}
	ctx, cancel := context.WithTimeout(s.ctx, 3*time.Second)
	defer cancel()
	tx, err := s.m.pg.BeginTx(ctx, nil)
	if err != nil {
		return
	}
	defer tx.Rollback()
	terminal := attempt >= investigationMaxAttempts
	next := "queued"
	if terminal {
		next = "failed"
	}
	res, err := tx.ExecContext(ctx, `
		UPDATE defense_investigation_runs
		  SET status=$3,last_error='Investigation database operation failed; review server logs',
		      lease_until=NULL,completed_at=CASE WHEN $3='failed' THEN now() ELSE NULL END
		WHERE id=$1 AND case_id=$2 AND status='running' AND attempts=$4`,
		runID, caseID, next, attempt)
	if err != nil {
		return
	}
	if affected, _ := res.RowsAffected(); affected != 1 {
		return
	}
	if err := appendInvestigationAudit(ctx, tx, runID, caseID, "failed",
		"investigator", "Read-only attempt failed; "+fmt.Sprintf("attempt %d/%d", attempt, investigationMaxAttempts)); err != nil {
		return
	}
	_ = tx.Commit()
}

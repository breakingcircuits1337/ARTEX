package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestInvestigationAutoIntakeIsOptInAndAuditedPG(t *testing.T) {
	t.Setenv("ARTEX_MODE", "defense")
	m := investigationTestManager(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := m.pg.ExecContext(ctx,
		`UPDATE defense_investigation_control SET auto_intake=false,paused=false WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = m.pg.ExecContext(context.Background(),
			`UPDATE defense_investigation_control SET auto_intake=false,paused=false WHERE id=1`)
	})
	var starting int
	if err := m.pg.QueryRowContext(ctx,
		`SELECT count(*) FROM defense_investigation_runs WHERE trigger_kind='auto_alert'`).
		Scan(&starting); err != nil {
		t.Fatal(err)
	}
	var eventID int64
	key := fmt.Sprintf("phase7-auto-%d", time.Now().UnixNano())
	if err := m.pg.QueryRowContext(ctx, `
		INSERT INTO defense_events(source,external_id,observed_at,kind,severity)
		VALUES('generic',$1,now(),'endpoint',7) RETURNING id`, key).Scan(&eventID); err != nil {
		t.Fatal(err)
	}
	if _, err := m.pg.ExecContext(ctx, `
		INSERT INTO defense_alerts
		(rule_id,title,severity,summary,event_id,correlation_key,window_start)
		VALUES('phase7_test','Synthetic high event','high',
		'Test-only alert for opt-in investigation case intake',$1,$2,now())`,
		eventID, key); err != nil {
		t.Fatal(err)
	}
	s := &Server{m: m, ctx: ctx}
	// A running worker with default OFF never creates an incident from a
	// newly received high-severity source alert.
	if err := s.intakeDefenseAlert(ctx); err != nil {
		t.Fatal(err)
	}
	var existing int
	if err := m.pg.QueryRowContext(ctx,
		`SELECT count(*) FROM defense_cases c JOIN defense_alerts a ON a.id=c.alert_id WHERE a.event_id=$1`,
		eventID).Scan(&existing); err != nil || existing != 0 {
		t.Fatalf("auto-intake ignored disabled control: cases=%d err=%v", existing, err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/defense/investigations/control",
		strings.NewReader(`{"auto_intake":true,"reason":"Authorized limited review of high severity alerts"}`))
	rec := httptest.NewRecorder()
	s.setInvestigationControl(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("enable auto intake status=%d: %s", rec.Code, rec.Body.String())
	}
	// The intake worker is globally bounded; only one candidate can be
	// admitted per call, and the side effect is a new case and review job.
	if err := s.intakeDefenseAlert(ctx); err != nil {
		t.Fatal(err)
	}
	var added int
	if err := m.pg.QueryRowContext(ctx,
		`SELECT count(*) FROM defense_investigation_runs WHERE trigger_kind='auto_alert'`).
		Scan(&added); err != nil || added != starting+1 {
		t.Fatalf("expected one rate-limited auto-review case, before=%d after=%d err=%v",
			starting, added, err)
	}
	var audited int
	if err := m.pg.QueryRowContext(ctx, `
		SELECT count(*) FROM defense_investigation_control_audit
		WHERE auto_intake=true AND reason=$1`,
		"Authorized limited review of high severity alerts").Scan(&audited); err != nil || audited < 1 {
		t.Fatalf("operator configuration not audited: %d %v", audited, err)
	}
	// There is never an emergency action for the newly ingested indicator.
	var actions int
	if err := m.pg.QueryRowContext(ctx,
		`SELECT count(*) FROM defense_emergency_actions WHERE event_id=$1`,
		eventID).Scan(&actions); err != nil || actions != 0 {
		t.Fatalf("auto case intake affected containment: count=%d err=%v", actions, err)
	}
}

func TestQueuedInvestigationCanBeCancelledPG(t *testing.T) {
	t.Setenv("ARTEX_MODE", "defense")
	m := investigationTestManager(t)
	caseID, _ := investigationTestCase(t, m, "cancel", "low")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	tx, err := m.pg.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	runID, queued, err := enqueueDefenseInvestigation(ctx, tx, caseID, "operator")
	if err != nil || !queued {
		t.Fatalf("queue failed id=%d queued=%v err=%v", runID, queued, err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	s := &Server{m: m}
	makeRequest := func() *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost,
			fmt.Sprintf("/api/defense/investigations/%d/cancel", runID),
			strings.NewReader(`{"reason":"Operator cancelled investigation pending sensor verification"}`))
		req.SetPathValue("id", fmt.Sprint(runID))
		rec := httptest.NewRecorder()
		s.cancelDefenseInvestigation(rec, req)
		return rec
	}
	if rec := makeRequest(); rec.Code != 200 {
		t.Fatalf("cancel status=%d %s", rec.Code, rec.Body.String())
	}
	if rec := makeRequest(); rec.Code != 409 {
		t.Fatalf("second cancellation should conflict, status=%d", rec.Code)
	}
	var status string
	if err := m.pg.QueryRowContext(ctx,
		`SELECT status FROM defense_investigation_runs WHERE id=$1`, runID).
		Scan(&status); err != nil || status != "cancelled" {
		t.Fatalf("cancel not durable, status=%s err=%v", status, err)
	}
	var findings int
	if err := m.pg.QueryRowContext(ctx,
		`SELECT count(*) FROM defense_investigation_findings WHERE run_id=$1`,
		runID).Scan(&findings); err != nil || findings != 0 {
		t.Fatalf("cancelled job created evidence: %d err=%v", findings, err)
	}
}

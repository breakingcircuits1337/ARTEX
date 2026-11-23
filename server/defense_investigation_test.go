package server

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func investigationTestManager(t *testing.T) *Manager {
	t.Helper()
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		if os.Getenv("ARTEX_PG_DSN") == "" {
			db.SkipPGUnavailable(t, err)
		}
		t.Fatalf("configured test PostgreSQL must not silently skip: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

func investigationTestCase(t *testing.T, m *Manager, suffix, severity string) (caseID, eventID int64) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	tx, err := m.pg.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	key := fmt.Sprintf("phase7-%s-%d", suffix, time.Now().UnixNano())
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO defense_events
		(source,external_id,observed_at,kind,src_ip,dst_ip,severity)
		VALUES('suricata',$1,now(),'network','198.51.100.47','192.0.2.12',6)
		RETURNING id`, key).Scan(&eventID); err != nil {
		t.Fatal(err)
	}
	var alertID int64
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO defense_alerts
		(rule_id,title,severity,summary,event_id,correlation_key,window_start)
		VALUES('phase7_test','Unverified synthetic sensor alert',$1,
		 'Generated only for autonomous investigation regression tests',
		 $2,$3,now()) RETURNING id`, severity, eventID, key).Scan(&alertID); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRowContext(ctx,
		`INSERT INTO defense_cases(alert_id) VALUES($1) RETURNING id`, alertID).
		Scan(&caseID); err != nil {
		t.Fatal(err)
	}
	if _, err := correlateDefenseCase(ctx, tx, caseID, "correlator"); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return caseID, eventID
}

func TestDefensiveInvestigatorEvidenceOnlyPG(t *testing.T) {
	m := investigationTestManager(t)
	caseID, eventID := investigationTestCase(t, m, "evidence", "low")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	tx, err := m.pg.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	runID, ok, err := enqueueDefenseInvestigation(ctx, tx, caseID, "operator")
	if err != nil || !ok {
		t.Fatalf("queue: id=%d created=%v err=%v", runID, ok, err)
	}
	if _, ok, err := enqueueDefenseInvestigation(ctx, tx, caseID, "operator"); err != nil || ok {
		t.Fatalf("same active case was queued twice: created=%v err=%v", ok, err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var attempt int
	err = m.pg.QueryRowContext(ctx, `
		UPDATE defense_investigation_runs
		   SET status='running',attempts=1,lease_until=now()+interval '30 seconds'
		 WHERE id=$1 RETURNING attempts`, runID).Scan(&attempt)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{m: m, ctx: ctx}
	if err := s.executeDefenseInvestigation(ctx, runID, caseID, attempt); err != nil {
		t.Fatal(err)
	}
	// Running the same attempt twice never creates another finding or audit.
	if err := s.executeDefenseInvestigation(ctx, runID, caseID, attempt); err != nil {
		t.Fatal(err)
	}
	var state string
	var findings int
	if err := m.pg.QueryRowContext(ctx,
		`SELECT status FROM defense_investigation_runs WHERE id=$1`, runID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "completed" {
		t.Fatalf("unexpected run status %s", state)
	}
	if err := m.pg.QueryRowContext(ctx, `
		SELECT count(*) FROM defense_investigation_findings
		WHERE run_id=$1 AND evidence_event_id=$2`, runID, eventID).Scan(&findings); err != nil {
		t.Fatal(err)
	}
	if findings != 2 {
		t.Fatalf("expected alert context and uncertainty, got %d", findings)
	}
	var wrong int
	if err := m.pg.QueryRowContext(ctx, `
		SELECT count(*) FROM defense_investigation_findings
		WHERE run_id=$1 AND confidence>55`, runID).Scan(&wrong); err != nil || wrong != 0 {
		t.Fatalf("analysis generated excessive certainty count=%d err=%v", wrong, err)
	}
	if err := m.pg.QueryRowContext(ctx, `
		SELECT count(*) FROM defense_emergency_actions WHERE event_id=$1`, eventID).Scan(&wrong); err != nil || wrong != 0 {
		t.Fatalf("investigator triggered containment count=%d err=%v", wrong, err)
	}
}

func TestInvestigationHumanReviewIsImmutablePG(t *testing.T) {
	t.Setenv("ARTEX_MODE", "defense")
	m := investigationTestManager(t)
	caseID, eventID := investigationTestCase(t, m, "review", "low")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	tx, err := m.pg.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	runID, _, err := enqueueDefenseInvestigation(ctx, tx, caseID, "operator")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO defense_investigation_findings
		(run_id,case_id,category,title,explanation,confidence,evidence_event_id)
		VALUES($1,$2,'alert_context','Synthetic advisory only',
		'False-positive review is mandatory for the reported sensor event',20,$3)`,
		runID, caseID, eventID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var findingID int64
	if err := m.pg.QueryRowContext(ctx, `
		SELECT id FROM defense_investigation_findings WHERE run_id=$1`, runID).Scan(&findingID); err != nil {
		t.Fatal(err)
	}
	s := &Server{m: m}
	makeReq := func(verdict string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/api/defense/investigations/findings/"+strconv.FormatInt(findingID, 10)+"/review",
			strings.NewReader(fmt.Sprintf(`{"verdict":%q,"reason":"Reviewed source evidence for a false positive"}`, verdict)))
		req.SetPathValue("id", strconv.FormatInt(findingID, 10))
		rec := httptest.NewRecorder()
		s.reviewDefenseFinding(rec, req)
		return rec
	}
	if result := makeReq("needs_more_evidence"); result.Code != 200 {
		t.Fatalf("review %d: %s", result.Code, result.Body.String())
	}
	if result := makeReq("supported"); result.Code != 409 {
		t.Fatalf("second conflicting review should be rejected: %d", result.Code)
	}
	// Evidence and its verdict both have immutable triggers, not editable fields.
	for _, stmt := range []string{
		`UPDATE defense_investigation_findings SET title='changed' WHERE id=$1`,
		`DELETE FROM defense_investigation_reviews WHERE finding_id=$1`,
	} {
		tx, err := m.pg.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, err = tx.ExecContext(ctx, stmt, findingID)
		_ = tx.Rollback()
		if err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Fatalf("immutable evidence mutation accepted or wrong error: %v", err)
		}
	}
}

func TestInvestigationQueueCancelAndPentestGates(t *testing.T) {
	t.Setenv("ARTEX_MODE", "pentest")
	s := &Server{}
	r := httptest.NewRequest(http.MethodGet, "/api/defense/investigations/control", nil)
	rec := httptest.NewRecorder()
	s.investigationControl(rec, r)
	if rec.Code != 404 {
		t.Fatalf("nondefense investigation route status %d", rec.Code)
	}
	t.Setenv("ARTEX_MODE", "defense")
	s = &Server{jwtKey: []byte(strings.Repeat("x", 32))}
	h := s.requireAuth(http.HandlerFunc(s.investigationControl))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != 401 {
		t.Fatalf("anonymous investigation control response %d", rec.Code)
	}
}

var _ *sql.Tx

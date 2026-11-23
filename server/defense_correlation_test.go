package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestCorrelationReadRoutesRequireDefenseAndSession(t *testing.T) {
	t.Setenv("ARTEX_MODE", "pentest")
	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/api/defense/cases/1/intelligence", nil)
	req.SetPathValue("id", "1")
	w := httptest.NewRecorder()
	s.getDefenseIntelligence(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("nondefense mode returned %d", w.Code)
	}
	t.Setenv("ARTEX_MODE", "defense")
	s = &Server{jwtKey: []byte(strings.Repeat("x", 32))}
	handler := s.requireAuth(http.HandlerFunc(s.refreshDefenseIntelligence))
	post := httptest.NewRequest(http.MethodPost, "/api/defense/cases/1/intelligence/refresh", nil)
	post.SetPathValue("id", "1")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, post)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized correlation refresh returned %d", w.Code)
	}
}

func TestThreatCorrelationPGIdempotentEvidenceGraphAndAudit(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		// An explicitly configured test DSN means the CI Postgres service
		// is expected to be available. Never silently skip migration errors.
		if strings.TrimSpace(os.Getenv("ARTEX_PG_DSN")) == "" {
			t.Skipf("no configured PostgreSQL test DSN: %v", err)
		}
		t.Fatalf("configured test database failed initialization: %v", err)
	}
	defer m.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	tx, err := m.pg.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()

	now := time.Now().UTC().Truncate(time.Second)
	prefix := fmt.Sprintf("phase6-correlation-%d", now.UnixNano())
	insertEvent := func(name, source, src, dst, host string, when time.Time) int64 {
		t.Helper()
		var id int64
		err := tx.QueryRowContext(ctx, `
			INSERT INTO defense_events
			 (source,external_id,observed_at,kind,src_ip,dst_ip,host,signature,severity)
			VALUES($1,$2,$3,'network',$4,$5,$6,'review-only',5) RETURNING id`,
			source, prefix+name, when, src, dst, host).Scan(&id)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	root := insertEvent("-anchor", "suricata", "198.51.100.9", "192.0.2.4", "srv.example", now)
	peer := insertEvent("-peer", "suricata", "198.51.100.9", "192.0.2.4", "srv.example", now.Add(time.Minute))
	_ = insertEvent("-different-dst", "suricata", "198.51.100.9", "192.0.2.77", "", now.Add(time.Minute))
	_ = insertEvent("-different-sensor", "wazuh", "198.51.100.9", "192.0.2.4", "srv.example", now.Add(time.Minute))
	_ = insertEvent("-stale", "suricata", "198.51.100.9", "192.0.2.4", "srv.example", now.Add(2*time.Hour))
	var alertID, caseID int64
	err = tx.QueryRowContext(ctx, `
		INSERT INTO defense_alerts
		 (rule_id,title,severity,summary,event_id,correlation_key,window_start)
		VALUES('password_spray_v1','Review-only test alert','medium','Test evidence',$1,$2,$3)
		RETURNING id`, root, prefix, now).Scan(&alertID)
	if err != nil {
		t.Fatal(err)
	}
	err = tx.QueryRowContext(ctx, `INSERT INTO defense_cases(alert_id) VALUES($1) RETURNING id`,
		alertID).Scan(&caseID)
	if err != nil {
		t.Fatal(err)
	}
	for pass := 0; pass < 2; pass++ {
		count, err := correlateDefenseCase(ctx, tx, caseID, "correlator")
		if err != nil {
			t.Fatal(err)
		}
		if count.Observations != 2 {
			t.Fatalf("correlated %d events, want anchor + matching peer", count.Observations)
		}
	}
	var observed, indicatorEvidence, edges, mappings int
	for _, q := range []struct {
		query string
		want  int
	}{
		{`SELECT count(*) FROM defense_case_observations WHERE case_id=$1`, 2},
		{`SELECT count(*) FROM defense_case_indicators WHERE case_id=$1`, 4},
		{`SELECT count(*) FROM defense_case_relations WHERE case_id=$1`, 2},
		{`SELECT count(*) FROM defense_case_techniques WHERE case_id=$1`, 1},
	} {
		var got int
		if err := tx.QueryRowContext(ctx, q.query, caseID).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != q.want {
			t.Fatalf("query %s returned %d, want %d", q.query, got, q.want)
		}
	}
	if err := tx.QueryRowContext(ctx, `
		SELECT count(*) FROM defense_indicator_evidence WHERE case_id=$1`,
		caseID).Scan(&indicatorEvidence); err != nil {
		t.Fatal(err)
	}
	if indicatorEvidence < 4 {
		t.Fatalf("missing source-event provenance for indicators: %d", indicatorEvidence)
	}
	if err := tx.QueryRowContext(ctx, `
		SELECT count(*) FROM defense_case_observations WHERE case_id=$1`,
		caseID).Scan(&observed); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRowContext(ctx, `
		SELECT count(*) FROM defense_case_relations WHERE case_id=$1`,
		caseID).Scan(&edges); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRowContext(ctx, `
		SELECT count(*) FROM defense_case_techniques WHERE case_id=$1`,
		caseID).Scan(&mappings); err != nil {
		t.Fatal(err)
	}
	if observed != 2 || edges != 2 || mappings != 1 {
		t.Fatalf("unexpected persisted graph: events=%d edges=%d mappings=%d", observed, edges, mappings)
	}
	if err := tx.QueryRowContext(ctx, `
		SELECT count(*) FROM defense_case_observations
		WHERE case_id=$1 AND event_id=$2`, caseID, peer).Scan(&observed); err != nil {
		t.Fatal(err)
	}
	if observed != 1 {
		t.Fatal("corroborating vendor event not linked")
	}

	// Attempts to alter the audit are rejected by the migration trigger.
	var auditID int64
	if err := tx.QueryRowContext(ctx,
		`SELECT id FROM defense_case_intel_audit WHERE case_id=$1 ORDER BY id LIMIT 1`,
		caseID).Scan(&auditID); err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`UPDATE defense_case_intel_audit SET detail='changed' WHERE id=$1`,
		`DELETE FROM defense_case_intel_audit WHERE id=$1`,
	} {
		if _, err := tx.ExecContext(ctx, `SAVEPOINT immutable_test`); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.ExecContext(ctx, stmt, auditID); err == nil {
			t.Fatal("append-only evidence audit was modified")
		}
		if _, err := tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT immutable_test`); err != nil {
			t.Fatal(err)
		}
	}
}

// Validates same-case constraints against an intentionally unrelated case.
// This is a rollback-only fixture; no scanner, remote endpoint or live
// containment is invoked by these tests.
func TestIndicatorCrossCaseEvidenceIsRejectedPG(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		// An explicitly configured test DSN means the CI Postgres service
		// is expected to be available. Never silently skip migration errors.
		if strings.TrimSpace(os.Getenv("ARTEX_PG_DSN")) == "" {
			t.Skipf("no configured PostgreSQL test DSN: %v", err)
		}
		t.Fatalf("configured test database failed initialization: %v", err)
	}
	defer m.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	tx, err := m.pg.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	makeCase := func(suffix string) (int64, int64) {
		t.Helper()
		var eventID, alertID, caseID int64
		key := fmt.Sprintf("phase6-cross-%s-%d", suffix, time.Now().UnixNano())
		err := tx.QueryRowContext(ctx, `
			INSERT INTO defense_events(source,external_id,observed_at,kind,severity,src_ip)
			VALUES('generic',$1,now(),'other',0,'192.0.2.1') RETURNING id`, key).Scan(&eventID)
		if err != nil {
			t.Fatal(err)
		}
		err = tx.QueryRowContext(ctx, `
			INSERT INTO defense_alerts(rule_id,title,severity,summary,event_id,correlation_key,window_start)
			VALUES('phase6', 'Test only', 'low', 'Test only',$1,$2,now()) RETURNING id`,
			eventID, key).Scan(&alertID)
		if err != nil {
			t.Fatal(err)
		}
		err = tx.QueryRowContext(ctx,
			`INSERT INTO defense_cases(alert_id) VALUES($1) RETURNING id`, alertID).Scan(&caseID)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := correlateDefenseCase(ctx, tx, caseID, "correlator"); err != nil {
			t.Fatal(err)
		}
		return caseID, eventID
	}
	first, _ := makeCase("one")
	second, secondEvent := makeCase("two")
	var firstIndicator int64
	if err := tx.QueryRowContext(ctx,
		`SELECT id FROM defense_case_indicators WHERE case_id=$1 LIMIT 1`,
		first).Scan(&firstIndicator); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `SAVEPOINT cross_case`); err != nil {
		t.Fatal(err)
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO defense_indicator_evidence(indicator_id,case_id,event_id,evidence_role,observed_at)
		VALUES($1,$2,$3,'source_ip',now())`, firstIndicator, second, secondEvent)
	if err == nil {
		t.Fatal("cross-case indicator provenance was accepted")
	}
	if _, err := tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT cross_case`); err != nil {
		t.Fatal(err)
	}
}

// Ensure a malformed case ID cannot accidentally trigger an expensive query.
func TestIntelligenceEndpointsRejectInvalidCaseID(t *testing.T) {
	t.Setenv("ARTEX_MODE", "defense")
	// Test the helper itself; database availability is checked only after
	// authentication/route match in the HTTP handler.
	r := httptest.NewRequest(http.MethodGet, "/api/defense/cases/nope/timeline", nil)
	r.SetPathValue("id", "nope")
	w := httptest.NewRecorder()
	if _, ok := workflowID(w, r); ok || w.Code != 400 {
		t.Fatalf("unexpected case-id gate response %d", w.Code)
	}
}


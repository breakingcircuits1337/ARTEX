package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

// The append-only constraint is tested inside one rollback-only transaction.
// This leaves no permanent synthetic security alerts, cases or audit entries
// behind in a shared PostgreSQL test database.
func TestDefenseAuditAppendOnlyPG(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		db.SkipPGUnavailable(t, err)
	}
	defer m.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	tx, err := m.pg.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()

	key := fmt.Sprintf("phase3-immutability-%d", time.Now().UnixNano())
	var eventID int64
	err = tx.QueryRowContext(ctx,
		`INSERT INTO defense_events(source,external_id,observed_at,kind,severity)
		 VALUES('generic',$1,now(),'other',0) RETURNING id`, key).Scan(&eventID)
	if err != nil {
		t.Fatal(err)
	}
	var alertID int64
	err = tx.QueryRowContext(ctx,
		`INSERT INTO defense_alerts(rule_id,title,severity,summary,event_id,correlation_key,window_start)
		 VALUES('phase3_test','Test alert','low','Not a real incident',$1,$2,now()) RETURNING id`,
		eventID, key).Scan(&alertID)
	if err != nil {
		t.Fatal(err)
	}
	var caseID int64
	err = tx.QueryRowContext(ctx,
		`INSERT INTO defense_cases(alert_id) VALUES($1) RETURNING id`, alertID).Scan(&caseID)
	if err != nil {
		t.Fatal(err)
	}
	var responseID int64
	err = tx.QueryRowContext(ctx,
		`INSERT INTO defense_response_requests(case_id,playbook,justification)
		 VALUES($1,'collect_additional_evidence','Operator reviewed normalized event') RETURNING id`,
		caseID).Scan(&responseID)
	if err != nil {
		t.Fatal(err)
	}
	if err := auditDefenseCase(ctx, tx, caseID, &responseID,
		"response_proposed", "Operator reviewed normalized event"); err != nil {
		t.Fatal(err)
	}
	var auditID int64
	err = tx.QueryRowContext(ctx,
		`SELECT id FROM defense_case_audit WHERE case_id=$1 AND response_id=$2`,
		caseID, responseID).Scan(&auditID)
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`UPDATE defense_case_audit SET reason='mutated' WHERE id=$1`,
		`DELETE FROM defense_case_audit WHERE id=$1`,
	} {
		if _, err := tx.ExecContext(ctx, `SAVEPOINT test_immutable`); err != nil {
			t.Fatal(err)
		}
		_, err := tx.ExecContext(ctx, stmt, auditID)
		if err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Fatalf("audit mutation was not rejected by trigger: %q error=%v", stmt, err)
		}
		if _, err := tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT test_immutable`); err != nil {
			t.Fatal(err)
		}
	}
}

// The existing ARTEX JWT middleware is the only public API authorization
// boundary. A case writer must not run without a valid session.
func TestDefenseCaseWriteRequiresSession(t *testing.T) {
	s := &Server{jwtKey: []byte(strings.Repeat("x", 32))}
	h := s.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodPost, "/api/defense/cases", strings.NewReader(`{"alert_id":1}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized case write returned %d", rec.Code)
	}
}

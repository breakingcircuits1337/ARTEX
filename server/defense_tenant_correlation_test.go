package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/defense"
)

func tenantTestManager(t *testing.T) *Manager {
	t.Helper()
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		if strings.TrimSpace(os.Getenv("ARTEX_PG_DSN")) == "" {
			t.Skipf("PostgreSQL unavailable without configured DSN: %v", err)
		}
		t.Fatalf("configured PostgreSQL failed to initialize: %v", err)
	}
	t.Cleanup(func() { m.Close() })
	return m
}
func tenantCompanies(t *testing.T, ctx context.Context, tx *sql.Tx, label string) (int64, int64) {
	t.Helper()
	var a, b int64
	for i, ptr := range []*int64{&a, &b} {
		key := fmt.Sprintf("%s-company-%d-%d", label, i, time.Now().UnixNano())
		if err := tx.QueryRowContext(ctx,
			`INSERT INTO companies(name,nkey) VALUES($1,$1) RETURNING id`, key).Scan(ptr); err != nil {
			t.Fatal(err)
		}
	}
	return a, b
}

func TestDefenseTenantAssetLinkPG(t *testing.T) {
	m := tenantTestManager(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	tx, err := m.pg.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	a, b := tenantCompanies(t, ctx, tx, "asset-scope")
	var aAsset, bAsset int64
	if err := tx.QueryRowContext(ctx, `INSERT INTO assets(type,ip,company_id)
        VALUES('ip','198.51.100.246',$1) RETURNING id`, a).Scan(&aAsset); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRowContext(ctx, `INSERT INTO assets(type,ip,company_id)
        VALUES('ip','198.51.100.247',$1) RETURNING id`, b).Scan(&bAsset); err != nil {
		t.Fatal(err)
	}
	// Even a single event carrying two different companies' IPs may link only
	// the inventory assets owned by the expressly enrolled company.
	event := defense.SecurityEvent{SrcIP: "198.51.100.247", DstIP: "198.51.100.246"}
	got, err := linkedDefenseAssets(ctx, tx, event, sql.NullInt64{Int64: a, Valid: true})
	if err != nil || len(got) != 1 || got[0] != aAsset {
		t.Fatalf("company A asset links=%v err=%v", got, err)
	}
	got, err = linkedDefenseAssets(ctx, tx, event, sql.NullInt64{Int64: b, Valid: true})
	if err != nil || len(got) != 1 || got[0] != bAsset {
		t.Fatalf("company B asset links=%v err=%v", got, err)
	}
	got, err = linkedDefenseAssets(ctx, tx, event, sql.NullInt64{})
	if err != nil || len(got) != 0 {
		t.Fatalf("unscoped legacy event leaked assets=%v err=%v", got, err)
	}
}

func TestDefenseCrossSensorSameCompanyPG(t *testing.T) {
	m := tenantTestManager(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	tx, err := m.pg.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	a, b := tenantCompanies(t, ctx, tx, "correlate")
	label := fmt.Sprintf("pr11-%d", time.Now().UnixNano())
	newCollector := func(name, source string, company int64) int64 {
		t.Helper()
		var id int64
		if err := tx.QueryRowContext(ctx, `INSERT INTO defense_collectors
            (name,source,token_hash,company_id) VALUES($1,$2,$3,$4) RETURNING id`,
			label+name, source, strings.Repeat("b", 64), company).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	a1 := newCollector("-a1", "suricata", a)
	a2 := newCollector("-a2", "wazuh", a)
	a3 := newCollector("-a3", "suricata", a)
	b1 := newCollector("-b1", "wazuh", b)
	now := time.Now().UTC().Truncate(time.Second)
	event := func(suffix, source string, collector any, company any, src, dst, host string, at time.Time) int64 {
		t.Helper()
		var id int64
		err := tx.QueryRowContext(ctx, `INSERT INTO defense_events
          (source,external_id,observed_at,kind,src_ip,dst_ip,host,signature,severity,collector_id,company_id)
          VALUES($1,$2,$3,'network',$4,$5,$6,'review-only',5,$7,$8) RETURNING id`,
			source, label+suffix, at, src, dst, host, collector, company).Scan(&id)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	src, dst, host := "203.0.113.55", "192.0.2.55", "server.example.test"
	anchor := event("-anchor", "suricata", a1, a, src, dst, host, now)
	independentPair := event("-same-company-pair", "wazuh", a2, a, src, dst, host, now.Add(time.Minute))
	independentHost := event("-same-company-host", "suricata", a3, a, src, "192.0.2.56", host, now.Add(time.Minute))
	otherTenant := event("-wrong-company", "wazuh", b1, b, src, dst, host, now.Add(time.Minute))
	_ = event("-unscoped", "suricata", nil, nil, src, dst, host, now.Add(time.Minute))
	_ = event("-one-field", "suricata", a3, a, src, "192.0.2.99", "other.test", now.Add(time.Minute))
	_ = event("-stale", "wazuh", a2, a, src, dst, host, now.Add(time.Hour))
	var alertID, caseID int64
	if err := tx.QueryRowContext(ctx, `INSERT INTO defense_alerts
        (rule_id,title,severity,summary,event_id,correlation_key,window_start)
        VALUES('phase11','Review-only','medium','Synthetic',$1,$2,$3) RETURNING id`,
		anchor, label, now).Scan(&alertID); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRowContext(ctx, `INSERT INTO defense_cases(alert_id)
        VALUES($1) RETURNING id`, alertID).Scan(&caseID); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		count, err := correlateDefenseCase(ctx, tx, caseID, "correlator")
		if err != nil {
			t.Fatal(err)
		}
		if count.Observations != 3 {
			t.Fatalf("pass %d: correlated %d; want alert + two independent sensors", i, count.Observations)
		}
	}
	checkReason := func(eventID int64, reason string, confidence int) {
		t.Helper()
		var gotReason string
		var gotConfidence int
		if err := tx.QueryRowContext(ctx, `SELECT link_reason,linkage_confidence
            FROM defense_case_observations WHERE case_id=$1 AND event_id=$2`,
			caseID, eventID).Scan(&gotReason, &gotConfidence); err != nil {
			t.Fatal(err)
		}
		if gotReason != reason || gotConfidence != confidence {
			t.Fatalf("event %d reason=%s confidence=%d want %s/%d",
				eventID, gotReason, gotConfidence, reason, confidence)
		}
	}
	checkReason(independentPair, "independent_collector_endpoints", 60)
	checkReason(independentHost, "independent_collector_host_ip", 55)
	var observed int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM defense_case_observations
        WHERE case_id=$1 AND event_id=$2`, caseID, otherTenant).Scan(&observed); err != nil {
		t.Fatal(err)
	}
	if observed != 0 {
		t.Fatal("cross-company event linked to case")
	}
	// The migration also rejects manual SQL attempts to insert cross-company
	// observations, regardless of which code path makes the insert.
	if _, err := tx.ExecContext(ctx, `SAVEPOINT reject_cross_company`); err != nil {
		t.Fatal(err)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO defense_case_observations
        (case_id,event_id,link_reason,linkage_confidence)
        VALUES($1,$2,'independent_collector_endpoints',60)`, caseID, otherTenant)
	if err == nil || !strings.Contains(err.Error(), "cross-company") {
		t.Fatalf("SQL guard allowed cross-company evidence: %v", err)
	}
	if _, err := tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT reject_cross_company`); err != nil {
		t.Fatal(err)
	}
	// A malicious/buggy direct SQL importer cannot write an event with
	// company B while claiming collector A's enrolled identity.
	if _, err := tx.ExecContext(ctx, `SAVEPOINT reject_source_company`); err != nil {
		t.Fatal(err)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO defense_events
        (source,external_id,observed_at,kind,severity,collector_id,company_id)
        VALUES('suricata',$1,now(),'other',0,$2,$3)`, label+"-spoof", a1, b)
	if err == nil || !strings.Contains(err.Error(), "event company differs") {
		t.Fatalf("SQL guard allowed spoofed collector company: %v", err)
	}
	if _, err := tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT reject_source_company`); err != nil {
		t.Fatal(err)
	}
}

func TestCollectorExistingUnboundOneWayCompanyBindingPG(t *testing.T) {
	t.Setenv("ARTEX_MODE", "defense")
	m := tenantTestManager(t)
	s := &Server{m: m, jwtKey: []byte(strings.Repeat("k", 32))}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var companyID int64
	name := fmt.Sprintf("scope-legacy-%d", time.Now().UnixNano())
	if err := m.pg.QueryRowContext(ctx, `INSERT INTO companies(name,nkey)
        VALUES($1,$1) RETURNING id`, name).Scan(&companyID); err != nil {
		t.Fatal(err)
	}
	var collectorID int64
	if err := m.pg.QueryRowContext(ctx, `INSERT INTO defense_collectors(name,source,token_hash)
        VALUES($1,'generic',$2) RETURNING id`, name, strings.Repeat("a", 64)).Scan(&collectorID); err != nil {
		t.Fatal(err)
	}
	var legacyEvent int64
	if err := m.pg.QueryRowContext(ctx, `INSERT INTO defense_events
        (source,external_id,observed_at,kind,severity,collector_id)
        VALUES('generic',$1,now(),'other',0,$2) RETURNING id`,
		name+"-before", collectorID).Scan(&legacyEvent); err != nil {
		t.Fatal(err)
	}
	token, err := signJWTVersion(s.jwtKey, 0)
	if err != nil {
		t.Fatal(err)
	}
	call := func(company int64) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost,
			fmt.Sprintf("/api/defense/collectors/%d/scope", collectorID),
			strings.NewReader(fmt.Sprintf(`{"company_id":%d}`, company)))
		req.SetPathValue("id", strconv.FormatInt(collectorID, 10))
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		s.collectorBindScope(rec, req)
		return rec
	}
	if res := call(companyID); res.Code != 200 {
		t.Fatalf("bind status=%d body=%s", res.Code, res.Body.String())
	}
	if res := call(companyID); res.Code != 409 {
		t.Fatalf("rebind status=%d body=%s", res.Code, res.Body.String())
	}
	var assigned, oldCompany sql.NullInt64
	if err := m.pg.QueryRowContext(ctx, `SELECT company_id FROM defense_collectors WHERE id=$1`, collectorID).Scan(&assigned); err != nil {
		t.Fatal(err)
	}
	if err := m.pg.QueryRowContext(ctx, `SELECT company_id FROM defense_events WHERE id=$1`, legacyEvent).Scan(&oldCompany); err != nil {
		t.Fatal(err)
	}
	if !assigned.Valid || assigned.Int64 != companyID || oldCompany.Valid {
		t.Fatalf("binding changed provenance: bound=%v legacy=%v", assigned, oldCompany)
	}
	var operations int
	if err := m.pg.QueryRowContext(ctx, `SELECT count(*) FROM defense_collector_audit
        WHERE collector_id=$1 AND operation='bound'`, collectorID).Scan(&operations); err != nil {
		t.Fatal(err)
	}
	if operations != 1 {
		t.Fatalf("expected one immutable scope assignment audit, got %d", operations)
	}
}

func TestDecodeDefenseCompanyScopeValidation(t *testing.T) {
	_, _, err := decodeDefenseBatchWithScope(strings.NewReader(`{"source":"generic","company_id":-1,"events":[{"kind":"other"}]}`), time.Now())
	if err == nil {
		t.Fatal("negative company scope accepted")
	}
	events, scope, err := decodeDefenseBatchWithScope(strings.NewReader(
		`{"source":"generic","company_id":42,"events":[{"kind":"other","event_id":"a"}]}`), time.Now())
	if err != nil || scope != 42 || len(events) != 1 {
		b, _ := json.Marshal(events)
		t.Fatalf("scoped batch scope=%d events=%s err=%v", scope, b, err)
	}
}

func TestUnscopedLegacyEvidenceAnchorOnlyPG(t *testing.T) {
	m := tenantTestManager(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	tx, err := m.pg.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	key := fmt.Sprintf("legacy-anchor-%d", time.Now().UnixNano())
	var anchor int64
	for i := 0; i < 2; i++ {
		var id int64
		err := tx.QueryRowContext(ctx, `INSERT INTO defense_events
			(source,external_id,observed_at,kind,src_ip,dst_ip,severity)
			VALUES('suricata',$1,now(),'network','203.0.113.45','192.0.2.45',5)
			RETURNING id`, fmt.Sprintf("%s-%d", key, i)).Scan(&id)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			anchor = id
		}
	}
	var alertID, caseID int64
	err = tx.QueryRowContext(ctx, `INSERT INTO defense_alerts
		(rule_id,title,severity,summary,event_id,correlation_key,window_start)
		VALUES('legacy','Legacy anchor','low','Unscoped test',$1,$2,now())
		RETURNING id`, anchor, key).Scan(&alertID)
	if err != nil {
		t.Fatal(err)
	}
	err = tx.QueryRowContext(ctx, `INSERT INTO defense_cases(alert_id)
		VALUES($1) RETURNING id`, alertID).Scan(&caseID)
	if err != nil {
		t.Fatal(err)
	}
	count, err := correlateDefenseCase(ctx, tx, caseID, "correlator")
	if err != nil || count.Observations != 1 {
		t.Fatalf("unscoped legacy peer linked: %+v err=%v", count, err)
	}
}

func TestTenantDatabaseImmutabilityPG(t *testing.T) {
	m := tenantTestManager(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	tx, err := m.pg.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	a, b := tenantCompanies(t, ctx, tx, "immutability")
	key := fmt.Sprintf("tenant-immutable-%d", time.Now().UnixNano())
	var collectorID int64
	err = tx.QueryRowContext(ctx, `INSERT INTO defense_collectors
		(name,source,token_hash,company_id)
		VALUES($1,'suricata',$2,$3) RETURNING id`,
		key, strings.Repeat("a", 64), a).Scan(&collectorID)
	if err != nil {
		t.Fatal(err)
	}
	var eventID int64
	err = tx.QueryRowContext(ctx, `INSERT INTO defense_events
		(source,external_id,observed_at,kind,severity,collector_id,company_id)
		VALUES('suricata',$1,now(),'other',0,$2,$3) RETURNING id`,
		key, collectorID, a).Scan(&eventID)
	if err != nil {
		t.Fatal(err)
	}
	for _, check := range []struct {
		sql  string
		arg  int64
		part string
	}{
		{`UPDATE defense_collectors SET company_id=$1 WHERE id=$2`, collectorID, "collector company binding is immutable"},
		{`UPDATE defense_events SET company_id=$1 WHERE id=$2`, eventID, "event collector and company provenance are immutable"},
	} {
		if _, err := tx.ExecContext(ctx, `SAVEPOINT tenant_immutable`); err != nil {
			t.Fatal(err)
		}
		_, err := tx.ExecContext(ctx, check.sql, b, check.arg)
		if err == nil || !strings.Contains(err.Error(), check.part) {
			t.Fatalf("immutable provenance update allowed: %s error=%v", check.sql, err)
		}
		if _, err := tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT tenant_immutable`); err != nil {
			t.Fatal(err)
		}
	}
}

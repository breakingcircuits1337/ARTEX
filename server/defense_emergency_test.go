package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/containment"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/defense"
)

type emergencyFakeRunner struct {
	applied  int
	reverted int
}

func (*emergencyFakeRunner) Check(context.Context) error { return nil }
func (f *emergencyFakeRunner) Apply(context.Context, string, time.Duration) error {
	f.applied++
	return nil
}
func (f *emergencyFakeRunner) Revert(context.Context, string) error {
	f.reverted++
	return nil
}

// The ARTEX process communicates only with a local Unix socket; it never
// needs privileges to execute nftables itself. This test uses a fake kernel.
func TestEmergencyUnixRPC(t *testing.T) {
	t.Setenv("ARTEX_MODE", "defense")
	t.Setenv("ARTEX_AUTO_CONTAIN_MODE", "nftables")
	t.Setenv("ARTEX_AUTO_CONTAIN_PROTECTED_CIDRS", "192.0.2.0/24")
	cfg, err := defense.LoadEmergencyConfig()
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(t.TempDir(), "emergency.sock")
	t.Setenv("ARTEX_AUTO_CONTAIN_SOCKET", socket)
	lis, err := net.Listen("unix", socket)
	if err != nil {
		t.Skipf("Unix sockets unavailable: %v", err)
	}
	defer lis.Close()
	fake := &emergencyFakeRunner{}
	backend := containment.Handler(cfg, fake)
	srv := &http.Server{Handler: backend}
	defer srv.Close()
	go func() { _ = srv.Serve(lis) }()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	client := nftEmergencyBackend{}
	if err := client.Check(ctx); err != nil {
		t.Fatal(err)
	}
	if err := client.Apply(ctx, "1.1.1.1", "192.0.2.2", 60*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := client.Revert(ctx, "1.1.1.1"); err != nil {
		t.Fatal(err)
	}
	if fake.applied != 1 || fake.reverted != 1 {
		t.Fatalf("unexpected Unix helper effects %+v", fake)
	}
}

func TestEmergencyRequiresAuthAndDefenseMode(t *testing.T) {
	t.Setenv("ARTEX_MODE", "pentest")
	s := &Server{}
	rec := httptest.NewRecorder()
	s.emergencyStatus(rec, httptest.NewRequest(http.MethodGet,
		"/api/defense/emergency/status", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("offensive mode exposed emergency controls: %d", rec.Code)
	}
	s = &Server{jwtKey: []byte(strings.Repeat("x", 32))}
	wrapped := s.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(204)
	}))
	rec = httptest.NewRecorder()
	wrapped.ServeHTTP(rec, httptest.NewRequest(http.MethodPost,
		"/api/defense/emergency/revert-all", nil))
	if rec.Code != 401 {
		t.Fatalf("anonymous panic-stop was allowed: %d", rec.Code)
	}
}

// Admission is verified in a single rollback-only PostgreSQL transaction;
// it leaves no synthetic alerts, actions, suppressions or audit records.
func TestEmergencyAdmissionPG(t *testing.T) {
	t.Setenv("ARTEX_MODE", "defense")
	t.Setenv("ARTEX_AUTO_CONTAIN_MODE", "simulate")
	t.Setenv("ARTEX_AUTO_CONTAIN_SURICATA_SIGNATURES", "Critical sensor signature")
	t.Setenv("ARTEX_AUTO_CONTAIN_PROTECTED_CIDRS", "192.0.2.0/24")
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		db.SkipPGUnavailable(t, err)
	}
	defer m.Close()
	s := &Server{m: m}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tx, err := m.pg.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx,
		"UPDATE defense_emergency_control SET paused=false WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	e := defense.SecurityEvent{
		Source: "suricata", Kind: "network", Action: "alert",
		SrcIP: "1.1.1.1", DstIP: "192.0.2.22",
		Signature: "Critical sensor signature", Severity: 9,
		VendorAlert: true, ObservedAt: now,
	}
	queued := 0
	for n := 1; n <= 4; n++ {
		var eventID int64
		key := fmt.Sprintf("emergency-stage-%d-%d", now.UnixNano(), n)
		err := tx.QueryRowContext(ctx, `
			INSERT INTO defense_events
			 (source,external_id,observed_at,kind,action,src_ip,dst_ip,
			  signature,severity,vendor_alert)
			VALUES('suricata',$1,$2,'network','alert',$3,$4,$5,9,true)
			RETURNING id`, key, now, e.SrcIP, e.DstIP, e.Signature).Scan(&eventID)
		if err != nil {
			t.Fatal(err)
		}
		id, err := s.stageEmergencyAction(ctx, tx, e, eventID, now)
		if err != nil {
			t.Fatal(err)
		}
		if n < 3 && id != 0 {
			t.Fatalf("action before corroboration at event %d", n)
		}
		if id != 0 {
			queued++
		}
	}
	if queued != 1 {
		t.Fatalf("corroboration/duplicate source guard queued %d actions", queued)
	}
	var written, audited int
	if err := tx.QueryRowContext(ctx, `
		SELECT count(*) FROM defense_emergency_actions
		WHERE source_ip='1.1.1.1' AND status='pending'`).Scan(&written); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRowContext(ctx, `
		SELECT count(*) FROM defense_emergency_audit
		WHERE event_type='queued'`).Scan(&audited); err != nil {
		t.Fatal(err)
	}
	if written == 0 || audited == 0 {
		t.Fatal("admitted action missing durable intent or audit")
	}
}

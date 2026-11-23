package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestOpsIngestCounterAndHistogramNoDynamicLabels(t *testing.T) {
	var m defenseIngestRuntime
	m.observe(200, 8*time.Millisecond)
	m.observe(400, 30*time.Millisecond)
	m.observe(429, 200*time.Millisecond)
	m.observe(503, 6*time.Second)
	counts := m.counts()
	if counts.Total != 4 || counts.Accepted != 1 || counts.Rejected != 1 ||
		counts.Limited != 1 || counts.Failed != 1 {
		t.Fatalf("bad ingestion counters %+v", counts)
	}
	for i, want := range []uint64{1, 2, 3, 3, 3, 4} {
		if got := m.latency[i].Load(); got != want {
			t.Errorf("bucket %d got %d want %d", i, got, want)
		}
	}
	if counts.DurationSeconds < 6 || counts.DurationSeconds >= 7 {
		t.Fatalf("nonfunctional latency sum: %v", counts.DurationSeconds)
	}
}

func TestOpsCacheSingleFlightAndErrorRetry(t *testing.T) {
	var cache defenseOpsCache
	var n atomic.Int64
	started := make(chan struct{})
	release := make(chan struct{})
	fetch := func(_ context.Context) (defenseOpsSnapshot, error) {
		if n.Add(1) == 1 {
			close(started)
			<-release
		}
		return defenseOpsSnapshot{Status: "ready", DatabaseReady: true}, nil
	}
	const workers = 12
	var wg sync.WaitGroup
	errCh := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			snap, err := cache.get(context.Background(), fetch)
			if err != nil || !snap.DatabaseReady {
				errCh <- fmt.Errorf("bad cache: %+v, %v", snap, err)
			}
		}()
	}
	<-started
	close(release)
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
	if n.Load() != 1 {
		t.Fatalf("cache fanned out %d SQL calls", n.Load())
	}
}

func TestOpsEndpointsRequireDefenseAndAdmin(t *testing.T) {
	s := &Server{jwtKey: []byte(strings.Repeat("s", 32))}
	for _, p := range []string{"/api/defense/operations/health", "/api/defense/operations/metrics"} {
		handler := http.HandlerFunc(s.defenseOperationsHealth)
		if strings.HasSuffix(p, "/metrics") {
			handler = s.defenseOperationsMetrics
		}
		t.Setenv("ARTEX_MODE", "pentest")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		if rec.Code != 404 {
			t.Fatalf("%s was active outside defense mode %d", p, rec.Code)
		}
		t.Setenv("ARTEX_MODE", "defense")
		wrapped := s.requireAuth(handler)
		rec = httptest.NewRecorder()
		wrapped.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		if rec.Code != 401 {
			t.Fatalf("%s accepted anonymous access: %d", p, rec.Code)
		}
		rec = httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, p, nil)
		req.Header.Set("Authorization", "Collector dc1.123.unsafe")
		wrapped.ServeHTTP(rec, req)
		if rec.Code != 401 {
			t.Fatalf("%s accepted collector credential: %d", p, rec.Code)
		}
		rec = httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		if rec.Code != 503 {
			t.Fatalf("%s faked database readiness: %d", p, rec.Code)
		}
	}
}

func TestOpsReadOnlyMetricsAndNoSensitiveLabelsPG(t *testing.T) {
	t.Setenv("ARTEX_MODE", "defense")
	m := tenantTestManager(t)
	s := &Server{m: m}
	name := fmt.Sprintf("pr13-ops-%d", time.Now().UnixNano())
	var companyID int64
	if err := m.pg.QueryRow(`INSERT INTO companies(name,nkey) VALUES($1,$1) RETURNING id`, name).Scan(&companyID); err != nil {
		t.Fatal(err)
	}
	var collectorID int64
	secret := "should-not-appear-in-metrics"
	if err := m.pg.QueryRow(`INSERT INTO defense_collectors
        (name,source,token_hash,company_id) VALUES($1,'generic',$2,$3) RETURNING id`,
		name, strings.Repeat("f", 64), companyID).Scan(&collectorID); err != nil {
		t.Fatal(err)
	}
	// A successful operator-scoped event exists, but telemetry details may
	// never be exported through operations or the Prometheus scrape path.
	eventKey := name + "-private-event"
	sourceIP := "203.0.113.153"
	event := fmt.Sprintf(`{"source":"generic","company_id":%d,"events":[
      {"event_id":"%s","kind":"authentication","outcome":"failure",
       "src_ip":"%s","username":"%s"}]}`, companyID, eventKey, sourceIP, secret)
	rec := httptest.NewRecorder()
	s.ingestDefenseEvents(rec, httptest.NewRequest(http.MethodPost, "/api/defense/events", strings.NewReader(event)))
	if rec.Code != 200 {
		t.Fatalf("ingest=%d %s", rec.Code, rec.Body.String())
	}
	var before, after int
	if err := m.pg.QueryRow(`SELECT count(*) FROM defense_events WHERE external_id=$1`, eventKey).Scan(&before); err != nil {
		t.Fatal(err)
	}
	health := httptest.NewRecorder()
	s.defenseOperationsHealth(health, httptest.NewRequest(http.MethodGet, "/api/defense/operations/health", nil))
	if health.Code != 200 {
		t.Fatalf("health status=%d body=%s", health.Code, health.Body.String())
	}
	var body struct {
		Operations defenseOpsSnapshot `json:"operations"`
		Ingestion  ingestCounts       `json:"ingestion_process"`
	}
	if err := json.Unmarshal(health.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Operations.DatabaseReady || body.Operations.CollectorsActive < 1 ||
		body.Operations.EventsLast5m < 1 || body.Ingestion.Total != 1 ||
		body.Ingestion.Accepted != 1 || body.Operations.AsOf.IsZero() {
		t.Fatalf("unexpected health response %+v", body)
	}
	if health.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("health must not be cached by proxy")
	}
	metrics := httptest.NewRecorder()
	s.defenseOperationsMetrics(metrics, httptest.NewRequest(http.MethodGet, "/api/defense/operations/metrics", nil))
	if metrics.Code != 200 {
		t.Fatalf("metrics status=%d body=%s", metrics.Code, metrics.Body.String())
	}
	data := metrics.Body.String()
	for _, field := range []string{"artex_defense_operations_database_ready 1",
		"artex_defense_ingest_handler_requests_total 1",
		`artex_defense_ingest_handler_duration_seconds_bucket{le="+Inf"} 1`,
		"# TYPE artex_defense_ingest_handler_duration_seconds histogram"} {
		if !strings.Contains(data, field) {
			t.Fatalf("missing Prometheus metric %q", field)
		}
	}
	for _, secretValue := range []string{sourceIP, secret, eventKey, name, "dc1.", "token_hash", "company_id", "collector_id"} {
		if strings.Contains(data, secretValue) || strings.Contains(health.Body.String(), secretValue) {
			t.Fatalf("sensitive metadata leaked into monitoring: %q", secretValue)
		}
	}
	if err := m.pg.QueryRow(`SELECT count(*) FROM defense_events WHERE external_id=$1`, eventKey).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if before != after || before != 1 {
		t.Fatal("observability changed event ledger")
	}
	var emergency int
	if err := m.pg.QueryRow(`SELECT count(*) FROM defense_emergency_actions
        WHERE event_id IN (SELECT id FROM defense_events WHERE external_id=$1)`, eventKey).Scan(&emergency); err != nil {
		t.Fatal(err)
	}
	if emergency != 0 {
		t.Fatal("observability created an emergency action")
	}
}

func TestOpsCacheExpiredContextAndStatusWriter(t *testing.T) {
	cache := &defenseOpsCache{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	if _, err := cache.get(ctx, func(context.Context) (defenseOpsSnapshot, error) {
		called = true
		return defenseOpsSnapshot{}, nil
	}); err == nil || called {
		t.Fatal("cancelled operation still ran SQL")
	}
	w := &ingestStatusWriter{ResponseWriter: httptest.NewRecorder()}
	if _, err := w.Write([]byte("ok")); err != nil || w.status != 200 {
		t.Fatal("status writer did not observe implicit success")
	}
	w.WriteHeader(500)
	if w.status != 200 {
		t.Fatal("duplicate WriteHeader incorrectly counted failure")
	}
}

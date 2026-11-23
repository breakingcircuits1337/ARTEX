package server

// Operational observability is an authenticated, read-only projection of
// existing PostgreSQL state, supplemented by process-local request counters.
// It is NOT sensor attestation, a multi-tenant security boundary or an SLA.
import (
	"context"
	"fmt"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defenseOpsCacheTTL        = 5 * time.Second
	defenseOpsErrorTTL        = time.Second
	defenseOpsQueryTimeout    = 5 * time.Second
	defenseOpsCollectorSample = 200
)

var defenseIngestBuckets = []struct {
	seconds  float64
	duration time.Duration
	text     string
}{
	{0.01, 10 * time.Millisecond, "0.01"},
	{0.05, 50 * time.Millisecond, "0.05"},
	{0.25, 250 * time.Millisecond, "0.25"},
	{1, time.Second, "1"},
	{5, 5 * time.Second, "5"},
	{20, 20 * time.Second, "20"},
}

// All counters reset on process restart and count *handler* requests only.
// In particular: credential failures blocked by outer JWT/collector middleware
// never reach the handler and do not count as ingestion attempts.
type defenseIngestRuntime struct {
	total         atomic.Uint64
	accepted      atomic.Uint64
	rejected      atomic.Uint64
	limited       atomic.Uint64
	failed        atomic.Uint64
	durationNanos atomic.Uint64
	latency       [6]atomic.Uint64 // 5 fixed bucket limits + Inf
}
type ingestCounts struct {
	Total           uint64  `json:"requests_total"`
	Accepted        uint64  `json:"accepted"`
	Rejected        uint64  `json:"rejected"`
	Limited         uint64  `json:"rate_limited"`
	Failed          uint64  `json:"failed"`
	DurationSeconds float64 `json:"duration_seconds_sum"`
}

func (m *defenseIngestRuntime) observe(status int, elapsed time.Duration) {
	m.total.Add(1)
	switch {
	case status >= 200 && status < 300:
		m.accepted.Add(1)
	case status == http.StatusTooManyRequests:
		m.limited.Add(1)
	case status >= 400 && status < 500:
		m.rejected.Add(1)
	default:
		m.failed.Add(1)
	}
	if elapsed < 0 {
		elapsed = 0
	}
	m.durationNanos.Add(uint64(elapsed.Nanoseconds()))
	for i, b := range defenseIngestBuckets {
		if elapsed <= b.duration {
			m.latency[i].Add(1)
		}
	}
	m.latency[len(m.latency)-1].Add(1)
}
func (m *defenseIngestRuntime) counts() ingestCounts {
	return ingestCounts{
		Total: m.total.Load(), Accepted: m.accepted.Load(), Rejected: m.rejected.Load(),
		Limited: m.limited.Load(), Failed: m.failed.Load(),
		DurationSeconds: float64(m.durationNanos.Load()) / float64(time.Second),
	}
}

// Using ResponseWriter status observation for this small JSON-only handler
// avoids new middleware on the machine-speed emergency, SSE or auth paths.
type ingestStatusWriter struct {
	http.ResponseWriter
	status int
}

func (w *ingestStatusWriter) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}
func (w *ingestStatusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

type defenseOpsSnapshot struct {
	AsOf                         time.Time `json:"as_of"`
	Status                       string    `json:"status"`
	DatabaseReady                bool      `json:"database_ready"`
	CollectorsActive             int64     `json:"collectors_active"`
	CollectorsRevoked            int64     `json:"collectors_revoked"`
	CollectorsUnassigned         int64     `json:"collectors_unassigned"`
	CollectorSampled             int64     `json:"collector_sampled"`
	CollectorNeverSeen           int64     `json:"collectors_never_seen"`
	CollectorSilent15m           int64     `json:"collectors_silent_15m"`
	CollectorSampleTruncated     bool      `json:"collector_sample_truncated"`
	EventsLast5m                 int64     `json:"events_last_5m"`
	AlertsLast5m                 int64     `json:"alerts_last_5m"`
	AlertsLastHour               int64     `json:"alerts_last_hour"`
	InvestigationsQueued         int64     `json:"investigations_queued"`
	InvestigationsRunning        int64     `json:"investigations_running"`
	InvestigationsFailedLastHour int64     `json:"investigations_failed_last_hour"`
	EmergencyPending             int64     `json:"emergency_pending"`
	EmergencyActive              int64     `json:"emergency_active"`
	EmergencyFailedLastHour      int64     `json:"emergency_failed_last_hour"`
	EmergencyPaused              bool      `json:"emergency_paused"`
	InvestigatorPaused           bool      `json:"investigator_paused"`
	AutoIntakeEnabled            bool      `json:"auto_intake_enabled"`
	Warnings                     []string  `json:"warnings"`
	Interpretation               string    `json:"interpretation"`
}
type defenseOpsCache struct {
	mu      sync.Mutex
	checked time.Time
	value   defenseOpsSnapshot
	err     error
	pending chan struct{}
}

func (c *defenseOpsCache) get(ctx context.Context, getFresh func(context.Context) (defenseOpsSnapshot, error)) (defenseOpsSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return defenseOpsSnapshot{}, err
	}
	c.mu.Lock()
	ttl := defenseOpsCacheTTL
	if c.err != nil {
		ttl = defenseOpsErrorTTL
	}
	if !c.checked.IsZero() && time.Since(c.checked) < ttl {
		v, err := c.value, c.err
		c.mu.Unlock()
		return v, err
	}
	if pending := c.pending; pending != nil {
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			return defenseOpsSnapshot{}, ctx.Err()
		case <-pending:
			c.mu.Lock()
			v, err := c.value, c.err
			c.mu.Unlock()
			return v, err
		}
	}
	pending := make(chan struct{})
	c.pending = pending
	c.mu.Unlock()
	v, err := getFresh(ctx)
	c.mu.Lock()
	c.value, c.err, c.checked = v, err, time.Now()
	c.pending = nil
	close(pending)
	c.mu.Unlock()
	return v, err
}

// Snapshot queries use existing summary indexes and a bounded, 201-collector
// sample. No credentials, event payloads, IPs, usernames or tenant IDs leave.
func (s *Server) readDefenseOps(ctx context.Context) (defenseOpsSnapshot, error) {
	out := defenseOpsSnapshot{AsOf: time.Now().UTC(), Warnings: []string{},
		Interpretation: "No recent events does not establish collector failure or absence of threats. Metrics are process-local or database snapshots, not certified service levels.",
	}
	if s.m == nil || s.m.pg == nil {
		return out, errNoPostgres
	}
	pg := s.m.pg
	// Validate DB reachability, and fail closed if any required query fails.
	if err := pg.PingContext(ctx); err != nil {
		return out, err
	}
	if err := pg.QueryRowContext(ctx, `
        SELECT COUNT(*) FILTER(WHERE revoked_at IS NULL),
               COUNT(*) FILTER(WHERE revoked_at IS NOT NULL),
               COUNT(*) FILTER(WHERE company_id IS NULL AND revoked_at IS NULL)
        FROM defense_collectors`).Scan(&out.CollectorsActive, &out.CollectorsRevoked, &out.CollectorsUnassigned); err != nil {
		return out, err
	}
	// The sample cap prevents a runaway N+1 query on very large deployments.
	// Stale means 'no recent ingestion recorded', never 'sensor offline'.
	if err := pg.QueryRowContext(ctx, `
        WITH sampled AS (
          SELECT c.id,(SELECT e.ingested_at FROM defense_events e
            WHERE e.collector_id=c.id ORDER BY e.ingested_at DESC,e.id DESC LIMIT 1) AS last_ingest
          FROM defense_collectors c
          WHERE c.revoked_at IS NULL ORDER BY c.id DESC LIMIT 201
        )
        SELECT count(*),
               count(*) FILTER(WHERE last_ingest IS NULL),
               count(*) FILTER(WHERE last_ingest<now()-interval '15 minutes')
        FROM sampled`).Scan(&out.CollectorSampled, &out.CollectorNeverSeen, &out.CollectorSilent15m); err != nil {
		return out, err
	}
	out.CollectorSampleTruncated = out.CollectorSampled > defenseOpsCollectorSample
	if out.CollectorSampleTruncated {
		// Never publish partial counts as if they cover all collectors.
		out.CollectorSampled = defenseOpsCollectorSample
		out.CollectorNeverSeen = -1
		out.CollectorSilent15m = -1
		out.Warnings = append(out.Warnings, "collector_sample_incomplete")
	}
	if err := pg.QueryRowContext(ctx, `
        SELECT count(*) FROM defense_events
        WHERE ingested_at>now()-interval '5 minutes'`).Scan(&out.EventsLast5m); err != nil {
		return out, err
	}
	if err := pg.QueryRowContext(ctx, `
        SELECT count(*) FILTER(WHERE created_at>now()-interval '5 minutes'),count(*)
        FROM defense_alerts WHERE created_at>now()-interval '1 hour'`).
		Scan(&out.AlertsLast5m, &out.AlertsLastHour); err != nil {
		return out, err
	}
	if err := pg.QueryRowContext(ctx, `
        SELECT count(*) FILTER(WHERE status='queued'),
               count(*) FILTER(WHERE status='running')
        FROM defense_investigation_runs WHERE status IN ('queued','running')`).
		Scan(&out.InvestigationsQueued, &out.InvestigationsRunning); err != nil {
		return out, err
	}
	if err := pg.QueryRowContext(ctx, `
        SELECT count(*) FROM defense_investigation_runs
        WHERE status='failed' AND completed_at>now()-interval '1 hour'`).
		Scan(&out.InvestigationsFailedLastHour); err != nil {
		return out, err
	}
	if err := pg.QueryRowContext(ctx, `
        SELECT count(*) FILTER(WHERE status='pending'),
               count(*) FILTER(WHERE status='active')
        FROM defense_emergency_actions WHERE status IN ('pending','active')`).
		Scan(&out.EmergencyPending, &out.EmergencyActive); err != nil {
		return out, err
	}
	if err := pg.QueryRowContext(ctx, `
        SELECT count(*) FROM defense_emergency_actions
        WHERE status='failed' AND created_at>now()-interval '1 hour'`).
		Scan(&out.EmergencyFailedLastHour); err != nil {
		return out, err
	}
	if err := pg.QueryRowContext(ctx, `SELECT paused FROM defense_emergency_control WHERE id=1`).
		Scan(&out.EmergencyPaused); err != nil {
		return out, err
	}
	if err := pg.QueryRowContext(ctx, `SELECT paused,auto_intake FROM defense_investigation_control WHERE id=1`).
		Scan(&out.InvestigatorPaused, &out.AutoIntakeEnabled); err != nil {
		return out, err
	}
	out.DatabaseReady = true
	switch {
	case out.CollectorsActive == 0:
		out.Status = "unknown"
		out.Warnings = append(out.Warnings, "no_enrolled_active_collectors")
	case out.EmergencyFailedLastHour > 0 || out.InvestigationsFailedLastHour > 0 || out.InvestigationsQueued >= 100:
		out.Status = "attention"
	default:
		out.Status = "ready"
	}
	if out.CollectorsUnassigned > 0 {
		out.Warnings = append(out.Warnings, "collectors_require_company_binding")
	}
	if out.CollectorNeverSeen > 0 {
		out.Warnings = append(out.Warnings, "collector_has_no_telemetry")
	}
	if out.CollectorSilent15m > 0 {
		out.Warnings = append(out.Warnings, "collector_no_recent_telemetry")
	}
	if out.EmergencyFailedLastHour > 0 {
		out.Warnings = append(out.Warnings, "emergency_action_failed")
	}
	if out.InvestigationsFailedLastHour > 0 {
		out.Warnings = append(out.Warnings, "investigation_failed")
	}
	if out.InvestigationsQueued >= 100 {
		out.Warnings = append(out.Warnings, "investigation_backlog")
	}
	// 'ready' means DB and operations snapshot could be read; it is not
	// affirmative evidence sensors are online, or a safety approval.
	return out, nil
}
func (s *Server) defenseOpsRead(ctx context.Context) (defenseOpsSnapshot, error) {
	deadline, cancel := context.WithTimeout(ctx, defenseOpsQueryTimeout)
	defer cancel()
	return s.defenseOpsCache.get(deadline, s.readDefenseOps)
}

func (s *Server) defenseOperationsHealth(w http.ResponseWriter, r *http.Request) {
	if !s.defenseMode(w) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	state, err := s.defenseOpsRead(r.Context())
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, "defense operational telemetry unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"operations":        state,
		"ingestion_process": s.defenseIngest.counts(),
		"metrics_scope":     "database snapshot plus current process; in-memory counters reset at restart",
		"authentication":    "admin session required",
	})
}

// This is a deliberately restricted Prometheus text exposition, not an
// unauthenticated /metrics endpoint. It is a read-only operator resource.
func (s *Server) defenseOperationsMetrics(w http.ResponseWriter, r *http.Request) {
	if !s.defenseMode(w) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	snap, err := s.defenseOpsRead(r.Context())
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, "defense operational telemetry unavailable")
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	var b strings.Builder
	gauge := func(name, help string, value int64) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s gauge\n%s %d\n", name, help, name, name, value)
	}
	counter := func(name, help string, value uint64) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s counter\n%s %d\n", name, help, name, name, value)
	}
	flag := func(v bool) int64 {
		if v {
			return 1
		}
		return 0
	}
	gauge("artex_defense_operations_database_ready", "Successful read of required database health queries.", flag(snap.DatabaseReady))
	gauge("artex_defense_collectors_active", "Enrolled collectors not revoked.", snap.CollectorsActive)
	gauge("artex_defense_collectors_unassigned", "Active collectors without a verified company binding.", snap.CollectorsUnassigned)
	gauge("artex_defense_collectors_never_seen", "Collector sample without ingested events; minus one when sampling is incomplete.", snap.CollectorNeverSeen)
	gauge("artex_defense_collectors_silent_15m", "Collector sample without events in 15 minutes; minus one when sampling is incomplete.", snap.CollectorSilent15m)
	gauge("artex_defense_collector_sample_truncated", "True if last-ingest collector sample is incomplete.", flag(snap.CollectorSampleTruncated))
	gauge("artex_defense_events_last_5m", "Normalized events ingested in last five minutes.", snap.EventsLast5m)
	gauge("artex_defense_alerts_last_5m", "Alerts created in last five minutes.", snap.AlertsLast5m)
	gauge("artex_defense_alerts_last_hour", "Alerts created in last hour.", snap.AlertsLastHour)
	gauge("artex_defense_investigations_queued", "Queued evidence-only investigation runs.", snap.InvestigationsQueued)
	gauge("artex_defense_investigations_running", "Running evidence-only investigation runs.", snap.InvestigationsRunning)
	gauge("artex_defense_investigations_failed_last_hour", "Failed investigation runs completed within one hour.", snap.InvestigationsFailedLastHour)
	gauge("artex_defense_emergency_pending", "Pending emergency action ledger entries.", snap.EmergencyPending)
	gauge("artex_defense_emergency_active", "Active emergency action ledger entries.", snap.EmergencyActive)
	gauge("artex_defense_emergency_failed_last_hour", "Failed emergency actions created within one hour.", snap.EmergencyFailedLastHour)
	gauge("artex_defense_emergency_paused", "Operator emergency admission pause is engaged.", flag(snap.EmergencyPaused))
	gauge("artex_defense_investigator_paused", "Evidence-only investigator pause is engaged.", flag(snap.InvestigatorPaused))
	gauge("artex_defense_process_goroutines", "Current process goroutine count.", int64(runtime.NumGoroutine()))
	count := s.defenseIngest.counts()
	counter("artex_defense_ingest_handler_requests_total", "Ingestion handler calls on this process; excludes rejected outer authentication.", count.Total)
	counter("artex_defense_ingest_handler_accepted_total", "Successful ingestion handler calls on this process.", count.Accepted)
	counter("artex_defense_ingest_handler_rejected_total", "Four-hundred-series failures other than rate limits on this process.", count.Rejected)
	counter("artex_defense_ingest_handler_limited_total", "HTTP 429 ingestion handler calls on this process.", count.Limited)
	counter("artex_defense_ingest_handler_failed_total", "Server-side ingestion handler failures on this process.", count.Failed)
	b.WriteString("# HELP artex_defense_ingest_handler_duration_seconds Request processing latency of ingestion handler calls, in seconds.\n")
	b.WriteString("# TYPE artex_defense_ingest_handler_duration_seconds histogram\n")
	for i, bucket := range defenseIngestBuckets {
		fmt.Fprintf(&b, "artex_defense_ingest_handler_duration_seconds_bucket{le=%q} %d\n", bucket.text, s.defenseIngest.latency[i].Load())
	}
	fmt.Fprintf(&b, "artex_defense_ingest_handler_duration_seconds_bucket{le=\"+Inf\"} %d\n", s.defenseIngest.latency[5].Load())
	fmt.Fprintf(&b, "artex_defense_ingest_handler_duration_seconds_sum %s\n",
		strconv.FormatFloat(count.DurationSeconds, 'f', 6, 64))
	fmt.Fprintf(&b, "artex_defense_ingest_handler_duration_seconds_count %d\n", count.Total)
	_, _ = w.Write([]byte(b.String()))
}

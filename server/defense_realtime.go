package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Phase 8 deliberately uses indexed read-side watermarks rather than a
// trigger-updated single hot row or a per-event NOTIFY. Security ingestion
// and machine-speed emergency enforcement retain their existing fast path.
const (
	socStreamInterval  = 2 * time.Second
	socStreamHeartbeat = 15 * time.Second
	socStreamLifetime  = 2 * time.Minute
	socStreamLimit     = 16
)

var socStreamingSlots = make(chan struct{}, socStreamLimit)

type socRevision struct {
	Events            int64 `json:"events"`
	Alerts            int64 `json:"alerts"`
	CaseUpdatedMicros int64 `json:"case_updated_micros"`
}

func readSOCRevision(ctx context.Context, pg interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) (socRevision, error) {
	var out socRevision
	err := pg.QueryRowContext(ctx, `
		SELECT
		  COALESCE((SELECT max(id) FROM defense_events),0),
		  COALESCE((SELECT max(id) FROM defense_alerts),0),
		  COALESCE((SELECT (EXTRACT(EPOCH FROM max(updated_at))*1000000)::bigint FROM defense_cases),0)`).
		Scan(&out.Events, &out.Alerts, &out.CaseUpdatedMicros)
	return out, err
}

// /api/defense/live is an authenticated, short-lived SSE control channel.
// Only opaque counters, not event bodies, signatures, identifiers or source
// metadata, are emitted. Every reconnect sends a full current watermark.
// Clients then refetch existing authenticated SOC APIs; no cursor gaps occur.
func (s *Server) defenseLive(w http.ResponseWriter, r *http.Request) {
	if !s.defenseMode(w) {
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	if _, ok := w.(http.Flusher); !ok {
		writeErr(w, http.StatusInternalServerError, "streaming unsupported by proxy")
		return
	}
	select {
	case socStreamingSlots <- struct{}{}:
		defer func() { <-socStreamingSlots }()
	default:
		w.Header().Set("Retry-After", "3")
		writeErr(w, http.StatusServiceUnavailable, "too many SOC streams; use polling")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), socStreamLifetime)
	defer cancel()
	firstCtx, firstCancel := context.WithTimeout(ctx, 3*time.Second)
	last, err := readSOCRevision(firstCtx, pg)
	firstCancel()
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, "SOC event store unavailable")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-transform")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// A 3-second write deadline bounds slow/broken streaming clients.
	controller := http.NewResponseController(w)
	send := func(event string, data socRevision) error {
		body, err := json.Marshal(data)
		if err != nil {
			return err
		}
		if err := controller.SetWriteDeadline(time.Now().Add(3 * time.Second)); err != nil && !errors.Is(err, http.ErrNotSupported) {
			return err
		}
		_, err = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, body)
		if err == nil {
			err = controller.Flush()
		}
		return err
	}
	if err := send("revision", last); err != nil {
		return
	}
	poll := time.NewTicker(socStreamInterval)
	defer poll.Stop()
	heartbeat := time.NewTicker(socStreamHeartbeat)
	defer heartbeat.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-poll.C:
			queryCtx, queryCancel := context.WithTimeout(ctx, 1500*time.Millisecond)
			next, err := readSOCRevision(queryCtx, pg)
			queryCancel()
			if err != nil {
				_ = send("unavailable", socRevision{})
				return
			}
			if next != last {
				if err := send("revision", next); err != nil {
					return
				}
				last = next
			}
		case <-heartbeat.C:
			if err := controller.SetWriteDeadline(time.Now().Add(3 * time.Second)); err != nil && !errors.Is(err, http.ErrNotSupported) {
				return
			}
			if _, err := fmt.Fprint(w, ": heartbeat\n\n"); err != nil {
				return
			}
			if controller.Flush() != nil {
				return
			}
		}
	}
}

type socAlertReview struct {
	ID         int64     `json:"id"`
	EventID    int64     `json:"event_id"`
	CaseID     int64     `json:"case_id"`
	CaseStatus string    `json:"case_status"`
	RuleID     string    `json:"rule_id"`
	Title      string    `json:"title"`
	Summary    string    `json:"summary"`
	Severity   string    `json:"severity"`
	Priority   int       `json:"priority"`
	NeedsCase  bool      `json:"needs_case"`
	CreatedAt  time.Time `json:"created_at"`
	AssetIDs   []int64   `json:"asset_ids"`
}

func socPriority(severity string, needsCase bool) int {
	score := map[string]int{"critical": 90, "high": 65, "medium": 40, "low": 15}[severity]
	if needsCase {
		score += 10
	}
	return score // deterministic queue sorting, NOT a compromise probability
}

// A bounded, sorted human review queue. No automatic triage/case update is
// performed. Severity comes from the existing detector, not graph/LLM scores.
func (s *Server) defenseSOCQueue(w http.ResponseWriter, r *http.Request) {
	if !s.defenseMode(w) {
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	rows, err := pg.QueryContext(ctx, `
		SELECT a.id,a.event_id,COALESCE(c.id,0),COALESCE(c.status,'unassigned'),
		       a.rule_id,a.title,a.summary,a.severity,a.created_at,a.asset_ids
		FROM defense_alerts a
		LEFT JOIN defense_cases c ON c.alert_id=a.id
		WHERE c.id IS NULL OR c.status IN ('open','investigating')
		ORDER BY CASE a.severity
		    WHEN 'critical' THEN 4 WHEN 'high' THEN 3
		    WHEN 'medium' THEN 2 ELSE 1 END DESC,
		    CASE WHEN c.id IS NULL THEN 1 ELSE 0 END DESC,
		    a.created_at DESC,a.id DESC
		LIMIT 50`)
	if err != nil {
		writeErr(w, 503, "SOC review queue unavailable")
		return
	}
	defer rows.Close()
	items := make([]socAlertReview, 0, 50)
	for rows.Next() {
		var row socAlertReview
		var raw []byte
		if err := rows.Scan(&row.ID, &row.EventID, &row.CaseID, &row.CaseStatus,
			&row.RuleID, &row.Title, &row.Summary, &row.Severity, &row.CreatedAt, &raw); err != nil {
			writeErr(w, 503, "SOC queue read failed")
			return
		}
		if err := json.Unmarshal(raw, &row.AssetIDs); err != nil {
			writeErr(w, 503, "SOC queue asset data invalid")
			return
		}
		row.NeedsCase = row.CaseID == 0
		row.Priority = socPriority(row.Severity, row.NeedsCase)
		items = append(items, row)
	}
	if rows.Err() != nil {
		writeErr(w, 503, "SOC queue iteration failed")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"alerts": items,
		"note": "Priority is a deterministic review ordering based on rule severity and case assignment, not a probability of attack. No action is executed."})
}

func (s *Server) defenseSOCHealth(w http.ResponseWriter, r *http.Request) {
	if !s.defenseMode(w) {
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	var recentEvents5m, recentEvents1h, recentAlerts5m, recentAlerts1h int64
	if err := pg.QueryRowContext(ctx, `
		SELECT count(*) FILTER (WHERE ingested_at>now()-interval '5 minutes'),
		       count(*)
		FROM defense_events WHERE ingested_at>now()-interval '1 hour'`).
		Scan(&recentEvents5m, &recentEvents1h); err != nil {
		writeErr(w, 503, "SOC ingress metrics unavailable")
		return
	}
	if err := pg.QueryRowContext(ctx, `
		SELECT count(*) FILTER (WHERE created_at>now()-interval '5 minutes'),
		       count(*) FROM defense_alerts WHERE created_at>now()-interval '1 hour'`).
		Scan(&recentAlerts5m, &recentAlerts1h); err != nil {
		writeErr(w, 503, "SOC alert metrics unavailable")
		return
	}
	var lastIngest, lastObserved sql.NullTime
	var lastSource sql.NullString
	err := pg.QueryRowContext(ctx, `
		SELECT ingested_at,observed_at,source FROM defense_events
		ORDER BY ingested_at DESC,id DESC LIMIT 1`).Scan(&lastIngest, &lastObserved, &lastSource)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		writeErr(w, 503, "SOC sensor freshness unavailable")
		return
	}
	type sourceMetric struct {
		Source         string    `json:"source"`
		EventsLastHour int64     `json:"events_last_hour"`
		LastIngest     time.Time `json:"last_ingest"`
	}
	sources := make([]sourceMetric, 0, 4)
	rows, err := pg.QueryContext(ctx, `
		SELECT source,count(*),max(ingested_at) FROM defense_events
		WHERE ingested_at>now()-interval '1 hour'
		GROUP BY source ORDER BY source LIMIT 4`)
	if err != nil {
		writeErr(w, 503, "SOC source metrics unavailable")
		return
	}
	for rows.Next() {
		var item sourceMetric
		if err := rows.Scan(&item.Source, &item.EventsLastHour, &item.LastIngest); err != nil {
			rows.Close()
			writeErr(w, 503, "SOC source metrics scan failed")
			return
		}
		sources = append(sources, item)
	}
	scanErr := rows.Err()
	rows.Close()
	if scanErr != nil {
		writeErr(w, 503, "SOC source metrics failed")
		return
	}
	// Last observed and last ingested timestamps are shown separately. A
	// skewed sensor clock can yield a negative lag; never clamp or hide it.
	var skewSeconds any
	var lastIngress any
	var lastSensorAt any
	stale := true
	if lastIngest.Valid {
		lastIngress = lastIngest.Time
		lastSensorAt = lastObserved.Time
		skewSeconds = lastIngest.Time.Sub(lastObserved.Time).Seconds()
		stale = time.Since(lastIngest.Time) > 5*time.Minute
	}
	// If nothing has ever been ingested, "no recent events" cannot prove the
	// collector is down. Surface unknown rather than claiming an outage.
	health := "unknown"
	if lastIngest.Valid {
		health = "receiving"
		if stale {
			health = "no_recent_ingest"
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{
		"as_of":        time.Now().UTC(),
		"ingest_state": health, "last_ingested_at": lastIngress, "last_observed_at": lastSensorAt,
		"last_source": strings.TrimSpace(lastSource.String), "sensor_clock_lag_seconds": skewSeconds,
		"events_last_5m": recentEvents5m, "events_last_hour": recentEvents1h,
		"alerts_last_5m": recentAlerts5m, "alerts_last_hour": recentAlerts1h,
		"sources": sources, "freshness_threshold_seconds": 300,
		"note": "No recent ingest is not proof a sensor is down. Sensor clocks can differ; observations remain unverified.",
	})
}

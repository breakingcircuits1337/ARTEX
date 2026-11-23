package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/Autumn-27/artex/defense"
)

// The existing /api/* JWT + same-origin middleware protects all three routes.
// This first increment uses console bearer tokens, NOT anonymous sensor posts.
const maxDefenseBatch = 50
const maxDefenseBody = 1 << 20

type defenseBatch struct {
	Source string            `json:"source"`
	Events []json.RawMessage `json:"events"`
}

func decodeDefenseBatch(r io.Reader, now time.Time) ([]defense.SecurityEvent, error) {
	d := json.NewDecoder(io.LimitReader(r, maxDefenseBody+1))
	d.DisallowUnknownFields()
	var input defenseBatch
	if err := d.Decode(&input); err != nil {
		return nil, errors.New("invalid JSON envelope")
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return nil, errors.New("trailing JSON is not allowed")
	}
	if len(input.Events) < 1 || len(input.Events) > maxDefenseBatch {
		return nil, errors.New("events must contain 1..50 entries")
	}
	events := make([]defense.SecurityEvent, 0, len(input.Events))
	for _, raw := range input.Events {
		e, err := defense.NormalizeEvent(input.Source, raw, now)
		if err != nil {
			return nil, err
		}
		events = append(events, e)
	}
	return events, nil
}

func (s *Server) defenseMode(w http.ResponseWriter) bool {
	if !defense.Restricted() {
		writeErr(w, http.StatusNotFound, "defense telemetry requires ARTEX_MODE=defense")
		return false
	}
	return true
}

func (s *Server) ingestDefenseEvents(w http.ResponseWriter, r *http.Request) {
	if !s.defenseMode(w) {
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	r.Body = http.MaxBytesReader(w, r.Body, maxDefenseBody)
	events, err := decodeDefenseBatch(r.Body, time.Now())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	collector := collectorFromContext(r.Context())
	if r.URL.Path == "/api/defense/collector/events" {
		if collector == nil {
			writeErr(w, 401, "invalid collector credential")
			return
		}
		for _, e := range events {
			if e.Source != collector.Source {
				writeErr(w, 403, "collector source scope mismatch")
				return
			}
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	tx, err := pg.BeginTx(ctx, nil)
	if err != nil {
		writeErr(w, 503, "telemetry database unavailable")
		return
	}
	defer tx.Rollback()
	var collectorID any
	if collector != nil {
		valid, err := validateCollectorTransaction(ctx, tx, collector)
		if err != nil { writeErr(w, 503, "collector policy unavailable"); return }
		if !valid { writeErr(w, 401, "collector credential changed or revoked"); return }
		collectorID = collector.ID
		allowed, err := s.reserveCollectorBudget(ctx, tx, collector.ID, len(events))
		if err != nil {
			writeErr(w, 503, "collector rate policy unavailable")
			return
		}
		if !allowed {
			w.Header().Set("Retry-After", "60")
			writeErr(w, 429, "collector event rate exceeded (600 per minute)")
			return
		}
	}
	ingested, duplicates, alertCount, linked := 0, 0, 0, 0
	emergencyActionIDs := make([]int64, 0, 4)
	for _, e := range events {
		ids, err := linkedDefenseAssets(ctx, tx, e)
		if err != nil {
			writeErr(w, 503, "asset correlation unavailable")
			return
		}
		assetJSON, err := json.Marshal(ids)
		if err != nil {
			writeErr(w, 500, "asset serialization error")
			return
		}
		var id int64
		err = tx.QueryRowContext(ctx, `
   INSERT INTO defense_events
   (source,external_id,observed_at,kind,outcome,action,src_ip,dst_ip,host,username,signature,severity,vendor_alert,asset_ids,collector_id)
   VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14::jsonb,$15)
   ON CONFLICT DO NOTHING RETURNING id
  `, e.Source, e.ExternalID, e.ObservedAt, e.Kind, e.Outcome, e.Action, e.SrcIP, e.DstIP, e.Host, e.Username, e.Signature, e.Severity, e.VendorAlert, string(assetJSON), collectorID).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			duplicates++
			continue
		}
		if err != nil {
			writeErr(w, 503, "event persistence failed")
			return
		}
		ingested++
		if len(ids) > 0 {
			linked++
		}
		correlationKey := e.ExternalID
		if collector != nil {
			correlationKey = fmt.Sprintf("collector:%d:%s", collector.ID, correlationKey)
		}
		for _, hit := range defense.EvaluateEvent(e) {
			created, err := insertDefenseAlert(ctx, tx, id, correlationKey, e.ObservedAt, hit, assetJSON)
			if err != nil {
				writeErr(w, 503, "alert persistence failed")
				return
			}
			if created {
				alertCount++
			}
		}
		// Conservative password-spray indicator: five distinct user names from one
		// source IP in ten minutes. A heuristic, not proof of account compromise.
		if e.Kind == "authentication" && e.Outcome == "failure" && e.SrcIP != "" && e.Username != "" {
			var users int
			err = tx.QueryRowContext(ctx, `
    SELECT COUNT(DISTINCT lower(username)) FROM defense_events
    WHERE kind='authentication' AND outcome='failure' AND src_ip=$1
      AND username<>'' AND observed_at BETWEEN $2 AND $3
      AND collector_id IS NOT DISTINCT FROM $4::bigint
   `, e.SrcIP, e.ObservedAt.Add(-10*time.Minute), e.ObservedAt, collectorID).Scan(&users)
			if err != nil {
				writeErr(w, 503, "correlation query failed")
				return
			}
			if users >= 5 {
				hit := defense.RuleHit{RuleID: "password_spray_v1", Title: "Possible password spraying", Severity: "medium",
					Summary: "At least five distinct account names have recorded failed authentication events from one source IP in the preceding ten minutes; review identity logs before concluding."}
				bucket := e.ObservedAt.Truncate(10 * time.Minute)
				key := e.SrcIP
				if collector != nil {
					key = fmt.Sprintf("collector:%d:%s", collector.ID, key)
				}
				created, err := insertDefenseAlertAt(ctx, tx, id, key, bucket, hit, assetJSON)
				if err != nil {
					writeErr(w, 503, "correlation alert failed")
					return
				}
				if created {
					alertCount++
				}
			}
		}
		// Machine-speed fast path: deterministic corroboration and admission are
		// recorded in the same transaction as the source event. Never call the
		// firewall before the event + audit record commits.
		// Collector credentials have no enforcement authority. Emergency admission
		// remains isolated until an independently reviewed collector policy exists.
		var actionID int64
		var autoErr error
		if collector == nil {
			actionID, autoErr = s.stageEmergencyAction(ctx, tx, e, id, time.Now())
		}
		if autoErr != nil {
			writeErr(w, 503, "emergency admission unavailable")
			return
		}
		if actionID > 0 {
			emergencyActionIDs = append(emergencyActionIDs, actionID)
		}
	}
	if err := tx.Commit(); err != nil {
		writeErr(w, 503, "telemetry commit failed")
		return
	}
	// Apply immediately after commit; no LLM, manual queue, or polling delay.
	// The bounded restart reconciler catches a process crash between commit
	// and kernel enforcement. All actions remain viewable and reversible.
	s.dispatchEmergencyActions(emergencyActionIDs)
	writeJSON(w, http.StatusOK, map[string]any{"ingested": ingested, "duplicates": duplicates, "alerts_created": alertCount, "events_linked": linked, "emergency_actions_queued": len(emergencyActionIDs)})
}

// Correlates only to existing inventory. No reverse lookup, scan or HTTP call.
func linkedDefenseAssets(ctx context.Context, tx *sql.Tx, e defense.SecurityEvent) ([]int64, error) {
	if e.SrcIP == "" && e.DstIP == "" && e.Host == "" {
		return nil, nil
	}
	rows, err := tx.QueryContext(ctx, `
  SELECT id FROM assets
  WHERE ($1<>'' AND ip=$1) OR ($2<>'' AND ip=$2)
     OR ($3<>'' AND lower(domain)=lower($3))
  ORDER BY id LIMIT 32
 `, e.SrcIP, e.DstIP, e.Host)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := make([]int64, 0)
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func insertDefenseAlert(ctx context.Context, tx *sql.Tx, eventID int64, key string, when time.Time, hit defense.RuleHit, assets []byte) (bool, error) {
	return insertDefenseAlertAt(ctx, tx, eventID, key, when, hit, assets)
}
func insertDefenseAlertAt(ctx context.Context, tx *sql.Tx, eventID int64, key string, bucket time.Time, hit defense.RuleHit, assets []byte) (bool, error) {
	var id int64
	err := tx.QueryRowContext(ctx, `
  INSERT INTO defense_alerts(rule_id,title,severity,summary,event_id,correlation_key,window_start,asset_ids)
  VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb)
  ON CONFLICT(rule_id,correlation_key,window_start) DO NOTHING RETURNING id
 `, hit.RuleID, hit.Title, hit.Severity, hit.Summary, eventID, key, bucket, string(assets)).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

func defenseLimit(r *http.Request) int {
	n, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil || n < 1 {
		return 50
	}
	if n > 100 {
		return 100
	}
	return n
}

func (s *Server) listDefenseEvents(w http.ResponseWriter, r *http.Request) {
	if !s.defenseMode(w) {
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	rows, err := pg.QueryContext(r.Context(), `
  SELECT id,source,external_id,observed_at,kind,outcome,src_ip,dst_ip,host,username,signature,severity,asset_ids
  FROM defense_events ORDER BY observed_at DESC,id DESC LIMIT $1
 `, defenseLimit(r))
	if err != nil {
		writeErr(w, 503, "telemetry database unavailable")
		return
	}
	defer rows.Close()
	events := make([]map[string]any, 0)
	for rows.Next() {
		var id int64
		var source, key, kind, outcome, src, dst, host, user, signature string
		var t time.Time
		var severity int
		var assetJSON []byte
		if err := rows.Scan(&id, &source, &key, &t, &kind, &outcome, &src, &dst, &host, &user, &signature, &severity, &assetJSON); err != nil {
			writeErr(w, 503, "telemetry read failed")
			return
		}
		var assets []int64
		_ = json.Unmarshal(assetJSON, &assets)
		events = append(events, map[string]any{"id": id, "source": source, "external_id": key, "observed_at": t, "kind": kind, "outcome": outcome, "src_ip": src, "dst_ip": dst, "host": host, "username": user, "signature": signature, "severity": severity, "asset_ids": assets})
	}
	if err := rows.Err(); err != nil {
		writeErr(w, 503, "telemetry read failed")
		return
	}
	writeJSON(w, 200, map[string]any{"events": events})
}

func (s *Server) listDefenseAlerts(w http.ResponseWriter, r *http.Request) {
	if !s.defenseMode(w) {
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	rows, err := pg.QueryContext(r.Context(), `
  SELECT id,rule_id,title,severity,summary,event_id,created_at,asset_ids
  FROM defense_alerts ORDER BY created_at DESC,id DESC LIMIT $1
 `, defenseLimit(r))
	if err != nil {
		writeErr(w, 503, "alert database unavailable")
		return
	}
	defer rows.Close()
	alerts := make([]map[string]any, 0)
	for rows.Next() {
		var id, eventID int64
		var rule, title, severity, summary string
		var t time.Time
		var raw []byte
		if err := rows.Scan(&id, &rule, &title, &severity, &summary, &eventID, &t, &raw); err != nil {
			writeErr(w, 503, "alert read failed")
			return
		}
		var assetIDs []int64
		_ = json.Unmarshal(raw, &assetIDs)
		alerts = append(alerts, map[string]any{"id": id, "rule_id": rule, "title": title, "severity": severity, "summary": summary, "event_id": eventID, "created_at": t, "asset_ids": assetIDs})
	}
	if err := rows.Err(); err != nil {
		writeErr(w, 503, "alert read failed")
		return
	}
	writeJSON(w, 200, map[string]any{"alerts": alerts})
}

func (s *Server) defenseSummary(w http.ResponseWriter, r *http.Request) {
	if !s.defenseMode(w) {
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	var events, alerts, linked int64
	err := pg.QueryRowContext(r.Context(), `SELECT count(*),count(*) FILTER (WHERE jsonb_array_length(asset_ids)>0) FROM defense_events`).Scan(&events, &linked)
	if err != nil {
		writeErr(w, 503, "telemetry summary unavailable")
		return
	}
	if err = pg.QueryRowContext(r.Context(), `SELECT count(*) FROM defense_alerts`).Scan(&alerts); err != nil {
		writeErr(w, 503, "alert summary unavailable")
		return
	}
	writeJSON(w, 200, map[string]any{"events": events, "alerts": alerts, "linked_events": linked, "mode": "defense", "detection_model": "deterministic-v1"})
}

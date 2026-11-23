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
	CompanyID int64          `json:"company_id,omitempty"`
	Events []json.RawMessage `json:"events"`
}

func decodeDefenseBatchWithScope(r io.Reader, now time.Time) ([]defense.SecurityEvent, int64, error) {
	d := json.NewDecoder(io.LimitReader(r, maxDefenseBody+1))
	d.DisallowUnknownFields()
	var input defenseBatch
	if err := d.Decode(&input); err != nil {
		return nil, 0, errors.New("invalid JSON envelope")
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return nil, 0, errors.New("trailing JSON is not allowed")
	}
	if input.CompanyID < 0 { return nil, 0, errors.New("company_id must be nonnegative") }
	if len(input.Events) < 1 || len(input.Events) > maxDefenseBatch {
		return nil, 0, errors.New("events must contain 1..50 entries")
	}
	events := make([]defense.SecurityEvent, 0, len(input.Events))
	for _, raw := range input.Events {
		e, err := defense.NormalizeEvent(input.Source, raw, now)
		if err != nil {
			return nil, 0, err
		}
		events = append(events, e)
	}
	return events, input.CompanyID, nil
}

func decodeDefenseBatch(r io.Reader, now time.Time) ([]defense.SecurityEvent, error) {
 events, _, err := decodeDefenseBatchWithScope(r,now)
 return events,err
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
	events, requestedCompanyID, err := decodeDefenseBatchWithScope(r.Body, time.Now())
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
		if requestedCompanyID != 0 { writeErr(w,403,"collector cannot select another company"); return }
		if !collector.CompanyID.Valid { writeErr(w,409,"collector has no assigned company; bind its scope before ingestion"); return }
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
	companyID := sql.NullInt64{}
	if collector != nil {
		valid, err := validateCollectorTransaction(ctx, tx, collector)
		if err != nil {
			writeErr(w, 503, "collector policy unavailable")
			return
		}
		if !valid {
			writeErr(w, 401, "collector credential changed or revoked")
			return
		}
		collectorID = collector.ID
		companyID = collector.CompanyID
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
	// The admin legacy endpoint may explicitly assign an existing company;
	// absent scope is kept NULL and cannot link to any inventory asset.
	if collector == nil && requestedCompanyID > 0 {
		var exists bool
		if err := tx.QueryRowContext(ctx,`SELECT EXISTS(SELECT 1 FROM companies WHERE id=$1)`,requestedCompanyID).Scan(&exists);err != nil {
			writeErr(w,503,"company scope lookup unavailable");return
		}
		if !exists {writeErr(w,400,"unknown company_id");return}
		companyID = sql.NullInt64{Int64:requestedCompanyID,Valid:true}
	}
	ingested, duplicates, alertCount, linked := 0, 0, 0, 0
	emergencyActionIDs := make([]int64, 0, 4)
	for _, e := range events {
		ids, err := linkedDefenseAssets(ctx, tx, e, companyID)
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
   (source,external_id,observed_at,kind,outcome,action,src_ip,dst_ip,host,username,signature,severity,vendor_alert,asset_ids,collector_id,company_id)
   VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14::jsonb,$15,$16)
   ON CONFLICT DO NOTHING RETURNING id
  `, e.Source, e.ExternalID, e.ObservedAt, e.Kind, e.Outcome, e.Action, e.SrcIP, e.DstIP, e.Host, e.Username, e.Signature, e.Severity, e.VendorAlert, string(assetJSON), collectorID, companyID).Scan(&id)
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
		} else if companyID.Valid {
			correlationKey = fmt.Sprintf("company:%d:%s",companyID.Int64,correlationKey)
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
      AND company_id IS NOT DISTINCT FROM $5::bigint
   `, e.SrcIP, e.ObservedAt.Add(-10*time.Minute), e.ObservedAt, collectorID, companyID).Scan(&users)
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
				} else if companyID.Valid {
					key = fmt.Sprintf("company:%d:%s", companyID.Int64, key)
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
		if collector == nil && companyID.Valid {
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
func linkedDefenseAssets(ctx context.Context, tx *sql.Tx, e defense.SecurityEvent, company sql.NullInt64) ([]int64, error) {
	if !company.Valid || (e.SrcIP == "" && e.DstIP == "" && e.Host == "") {
		return nil, nil
	}
	rows, err := tx.QueryContext(ctx, `
  SELECT id FROM assets
  WHERE company_id=$4
    AND (($1<>'' AND ip=$1) OR ($2<>'' AND ip=$2)
      OR ($3<>'' AND lower(domain)=lower($3)))
  ORDER BY id LIMIT 32
 `, e.SrcIP, e.DstIP, e.Host, company.Int64)
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

// This is an admin-console filter, NOT tenant RBAC. All API callers still
// authenticate as the single privileged operator; no tenant-user roles exist.
func defenseCompanyFilter(w http.ResponseWriter,r *http.Request) (int64,bool) {
 raw:=r.URL.Query().Get("company_id")
 if raw=="" {return 0,true}
 id,err:=strconv.ParseInt(raw,10,64)
 if err!=nil || id<=0 {writeErr(w,400,"company_id must be a positive integer");return 0,false}
 return id,true
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
	scope,ok:=defenseCompanyFilter(w,r);if !ok{return}
	rows, err := pg.QueryContext(r.Context(), `
  SELECT id,source,external_id,observed_at,kind,outcome,src_ip,dst_ip,host,username,signature,severity,
         CASE WHEN company_id IS NOT NULL THEN asset_ids ELSE '[]'::jsonb END,
         company_id,collector_id
  FROM defense_events
  WHERE ($2::bigint=0 OR company_id=$2::bigint)
  ORDER BY observed_at DESC,id DESC LIMIT $1
 `, defenseLimit(r),scope)
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
		var companyID,collectorID sql.NullInt64
		if err := rows.Scan(&id, &source, &key, &t, &kind, &outcome, &src, &dst, &host, &user, &signature, &severity, &assetJSON, &companyID, &collectorID); err != nil {
			writeErr(w, 503, "telemetry read failed")
			return
		}
		var assets []int64
		_ = json.Unmarshal(assetJSON, &assets)
		var company,collector any
		if companyID.Valid{company=companyID.Int64}
		if collectorID.Valid{collector=collectorID.Int64}
		events = append(events, map[string]any{"id": id, "source": source, "external_id": key, "observed_at": t, "kind": kind, "outcome": outcome, "src_ip": src, "dst_ip": dst, "host": host, "username": user, "signature": signature, "severity": severity, "asset_ids": assets, "company_id":company, "collector_id":collector})
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
	scope,ok:=defenseCompanyFilter(w,r);if !ok{return}
	rows, err := pg.QueryContext(r.Context(), `
  SELECT a.id,a.rule_id,a.title,a.severity,a.summary,a.event_id,a.created_at,
         CASE WHEN e.company_id IS NOT NULL THEN a.asset_ids ELSE '[]'::jsonb END,
         e.company_id,e.collector_id
  FROM defense_alerts a JOIN defense_events e ON e.id=a.event_id
  WHERE ($2::bigint=0 OR e.company_id=$2::bigint)
  ORDER BY a.created_at DESC,a.id DESC LIMIT $1
 `, defenseLimit(r),scope)
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
		var companyID,collectorID sql.NullInt64
		if err := rows.Scan(&id, &rule, &title, &severity, &summary, &eventID, &t, &raw, &companyID, &collectorID); err != nil {
			writeErr(w, 503, "alert read failed")
			return
		}
		var assetIDs []int64
		_ = json.Unmarshal(raw, &assetIDs)
		var company,collector any
		if companyID.Valid{company=companyID.Int64}
		if collectorID.Valid{collector=collectorID.Int64}
		alerts = append(alerts, map[string]any{"id": id, "rule_id": rule, "title": title, "severity": severity, "summary": summary, "event_id": eventID, "created_at": t, "asset_ids": assetIDs, "company_id":company, "collector_id":collector})
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
	scope,ok:=defenseCompanyFilter(w,r);if !ok{return}
	var events, alerts, linked int64
	err := pg.QueryRowContext(r.Context(), `SELECT count(*),
	 count(*) FILTER (WHERE company_id IS NOT NULL AND jsonb_array_length(asset_ids)>0)
	 FROM defense_events WHERE ($1::bigint=0 OR company_id=$1::bigint)`,scope).Scan(&events, &linked)
	if err != nil {
		writeErr(w, 503, "telemetry summary unavailable")
		return
	}
	if err = pg.QueryRowContext(r.Context(), `SELECT count(*) FROM defense_alerts a
	JOIN defense_events e ON e.id=a.event_id
	WHERE ($1::bigint=0 OR e.company_id=$1::bigint)`,scope).Scan(&alerts); err != nil {
		writeErr(w, 503, "alert summary unavailable")
		return
	}
	writeJSON(w, 200, map[string]any{"events": events, "alerts": alerts, "linked_events": linked, "mode": "defense", "detection_model": "deterministic-v1"})
}

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSOCPriorityIsReviewOrderNotConfidence(t *testing.T) {
	for _, tc := range []struct {
		severity string
		assigned bool
		want int
	}{
		{"critical", false, 100}, {"high", false, 75},
		{"medium", false, 50}, {"low", false, 25},
		{"critical", true, 90}, {"high", true, 65},
	} {
		if got := socPriority(tc.severity, !tc.assigned); got != tc.want {
			t.Fatalf("priority(%s,assigned=%v)=%d want %d",
				tc.severity, tc.assigned, got, tc.want)
		}
	}
	if socPriority("high",true) >= socPriority("critical",false) {
		t.Fatal("lower severity outranks critical event without a case")
	}
}

func TestSOCEndpointsRequireDefenseModeAndSession(t *testing.T) {
	t.Setenv("ARTEX_MODE", "pentest")
	s := &Server{}
	for _, handler := range []http.HandlerFunc{s.defenseLive, s.defenseSOCQueue, s.defenseSOCHealth} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/defense/live", nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("nondefense endpoint returned %d", rec.Code)
		}
	}
	t.Setenv("ARTEX_MODE", "defense")
	s = &Server{jwtKey: []byte(strings.Repeat("x",32))}
	wrapped := s.requireAuth(http.HandlerFunc(s.defenseLive))
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/defense/live", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthed SOC stream returned %d", rec.Code)
	}
}

func TestSOCStreamCarriesOnlyRevisionWatermarksPG(t *testing.T) {
	t.Setenv("ARTEX_MODE", "defense")
	m := investigationTestManager(t)
	s := &Server{m:m}
	ctx,cancel := context.WithTimeout(context.Background(), 220*time.Millisecond)
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/api/defense/live", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	s.defenseLive(rec,req)
	if rec.Code != http.StatusOK {
		t.Fatalf("SSE status %d: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); !strings.Contains(got,"text/event-stream") {
		t.Fatalf("SSE content-type %q",got)
	}
	if got := rec.Header().Get("Cache-Control"); !strings.Contains(got, "no-store") {
		t.Fatalf("SSE cache headers missing: %q",got)
	}
	body := rec.Body.String()
	if !strings.Contains(body,"event: revision\ndata: ") ||
		!strings.Contains(body,"case_updated_micros") {
		t.Fatalf("missing initial resync frame: %s",body)
	}
	for _, forbidden := range []string{`"src_ip"`,`"username"`,`"signature"`,`"external_id"`} {
		if strings.Contains(body,forbidden) {
			t.Fatalf("SSE leaked security telemetry field %q: %s",forbidden,body)
		}
	}
}

func TestSOCReviewQueueAndHealthAreReadOnlyPG(t *testing.T) {
	t.Setenv("ARTEX_MODE", "defense")
	m := investigationTestManager(t)
	s := &Server{m:m}
	ctx,cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	key := fmt.Sprintf("phase8-queue-%d",time.Now().UnixNano())
	var eventID int64
	if err := m.pg.QueryRowContext(ctx, `
		INSERT INTO defense_events(source,external_id,observed_at,kind,signature,severity)
		VALUES('generic',$1,now(),'endpoint','SYNTHETIC-READ-ONLY',9) RETURNING id`, key).Scan(&eventID);err!=nil {
		t.Fatal(err)
	}
	var alertID int64
	if err := m.pg.QueryRowContext(ctx, `
		INSERT INTO defense_alerts(rule_id,title,severity,summary,event_id,correlation_key,window_start)
		VALUES('phase8_test','Synthetic critical review','critical',
		'Review-only source event for monitoring tests',$1,$2,now()) RETURNING id`,eventID,key).
		Scan(&alertID); err!=nil {t.Fatal(err)}

	rec:=httptest.NewRecorder()
	s.defenseSOCQueue(rec,httptest.NewRequest(http.MethodGet,"/api/defense/soc/queue",nil))
	if rec.Code!=200 {t.Fatalf("queue %d %s",rec.Code,rec.Body.String())}
	var queue struct {
		Alerts []socAlertReview `json:"alerts"`
	}
	if err:=json.Unmarshal(rec.Body.Bytes(),&queue);err!=nil {t.Fatal(err)}
	found:=false
	for _,row:=range queue.Alerts {
		if row.ID==alertID {
			found=true
			if row.Priority!=100 || !row.NeedsCase || row.EventID!=eventID || row.CaseID!=0 {
				t.Fatalf("incorrect priority/admission for unassigned alert: %+v",row)
			}
		}
	}
	if !found {t.Fatalf("expected synthetic critical review item in queue of %d",len(queue.Alerts))}
	rec=httptest.NewRecorder()
	s.defenseSOCHealth(rec,httptest.NewRequest(http.MethodGet,"/api/defense/soc/health",nil))
	if rec.Code!=200 {t.Fatalf("health %d %s",rec.Code,rec.Body.String())}
	var health struct{
		EventsLast5m int64 `json:"events_last_5m"`
		IngestState string `json:"ingest_state"`
		AsOf string `json:"as_of"`
	}
	if err:=json.Unmarshal(rec.Body.Bytes(),&health);err!=nil {t.Fatal(err)}
	if health.EventsLast5m<1 || health.IngestState!="receiving" || health.AsOf=="" {
		t.Fatalf("recent ingestion missing from health: %+v",health)
	}
	var cases,actions int
	if err:=m.pg.QueryRowContext(ctx,`SELECT count(*) FROM defense_cases WHERE alert_id=$1`,alertID).
		Scan(&cases);err!=nil {t.Fatal(err)}
	if err:=m.pg.QueryRowContext(ctx,`SELECT count(*) FROM defense_emergency_actions WHERE event_id=$1`,eventID).
		Scan(&actions);err!=nil {t.Fatal(err)}
	if cases!=0 || actions!=0 {
		t.Fatalf("read-only monitoring caused changes: cases=%d actions=%d",cases,actions)
	}
}

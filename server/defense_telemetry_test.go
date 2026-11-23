package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDecodeDefenseBatch(t *testing.T) {
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	body := `{"source":"generic","events":[{"event_id":"e1","kind":"authentication","outcome":"failure","src_ip":"192.0.2.1","username":"alice"}]}`
	events, err := decodeDefenseBatch(strings.NewReader(body), now)
	if err != nil || len(events) != 1 || events[0].ExternalID != "e1" {
		t.Fatalf("events=%+v err=%v", events, err)
	}
}

func TestDecodeDefenseBatchRejectsUntrustedInput(t *testing.T) {
	now := time.Now()
	for _, body := range []string{
		`{"source":"generic","events":[]}`,
		`{"source":"unsupported","events":[{}]}`,
		`{"source":"generic","events":[[]]}`,
		`{"source":"generic","events":[{"kind":"other"}],"extra":"unknown"}`,
		`{"source":"generic","events":[{"kind":"other"}]}{}`,
	} {
		if _, err := decodeDefenseBatch(strings.NewReader(body), now); err == nil {
			t.Errorf("accepted invalid envelope %s", body)
		}
	}
	tooMany := make([]json.RawMessage, 51)
	for i := range tooMany {
		tooMany[i] = json.RawMessage(`{"kind":"other"}`)
	}
	b, _ := json.Marshal(defenseBatch{Source: "generic", Events: tooMany})
	if _, err := decodeDefenseBatch(bytes.NewReader(b), now); err == nil {
		t.Fatal("accepted oversized batch")
	}
}

func TestDefenseDisabledOutsideDefenseMode(t *testing.T) {
	t.Setenv("ARTEX_MODE", "pentest")
	s := &Server{}
	rec := httptest.NewRecorder()
	s.defenseSummary(rec, httptest.NewRequest(http.MethodGet, "/api/defense/summary", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("defense route status=%d", rec.Code)
	}
}

func TestDefenseRequiresSession(t *testing.T) {
	t.Setenv("ARTEX_MODE", "defense")
	s := &Server{jwtKey: []byte(strings.Repeat("x", 32))}
	wrapped := s.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	r := httptest.NewRequest(http.MethodPost, "/api/defense/events", strings.NewReader(`{"source":"generic"}`))
	w := httptest.NewRecorder()
	wrapped.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous ingestion status=%d", w.Code)
	}
}

package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDetectionCatalogIsAlertOnly(t *testing.T) {
	t.Setenv("ARTEX_MODE", "defense")
	s := &Server{}
	w := httptest.NewRecorder()
	s.defenseDetectionCatalog(w, httptest.NewRequest(http.MethodGet, "/api/defense/detection-pack", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("catalog status=%d body=%s", w.Code, w.Body.String())
	}
	for _, fragment := range []string{
		`"policy":"alert_only"`,
		`"autonomous_containment":false`,
		`"automatic_activation":false`,
		`"quarantined_count":15`,
	} {
		if !strings.Contains(w.Body.String(), fragment) {
			t.Fatalf("catalog missing safety constraint %s", fragment)
		}
	}
}

func TestDetectionDownloadsFixedEngineNames(t *testing.T) {
	t.Setenv("ARTEX_MODE", "defense")
	s := &Server{}
	for _, tc := range []struct {
		engine     string
		wantStatus int
		content    string
	}{
		{"suricata", http.StatusOK, "sid:9900001;"},
		{"yara", http.StatusOK, "rule ARTEX_JSP_Webshell_Numbered"},
		{"../manifest.json", http.StatusNotFound, ""},
		{"shell", http.StatusNotFound, ""},
	} {
		req := httptest.NewRequest(http.MethodGet, "/api/defense/detection-pack/"+tc.engine, nil)
		req.SetPathValue("engine", tc.engine)
		rec := httptest.NewRecorder()
		s.defenseDetectionDownload(rec, req)
		if rec.Code != tc.wantStatus {
			t.Errorf("%s: status=%d body=%s", tc.engine, rec.Code, rec.Body.String())
		}
		if tc.wantStatus == http.StatusOK {
			if !strings.Contains(rec.Body.String(), tc.content) || rec.Header().Get("Content-Disposition") == "" {
				t.Errorf("%s: invalid rule file response", tc.engine)
			}
		}
	}
}

func TestDetectionCatalogRequiresDefenseMode(t *testing.T) {
	t.Setenv("ARTEX_MODE", "pentest")
	s := &Server{}
	rec := httptest.NewRecorder()
	s.defenseDetectionCatalog(rec, httptest.NewRequest(http.MethodGet, "/api/defense/detection-pack", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("detection catalog exposed in pentest mode: %d", rec.Code)
	}
}

func TestDetectionCatalogRequiresSession(t *testing.T) {
	s := &Server{jwtKey: []byte(strings.Repeat("x", 32))}
	h := s.requireAuth(http.HandlerFunc(s.defenseDetectionCatalog))
	req := httptest.NewRequest(http.MethodGet, "/api/defense/detection-pack", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous catalog request status=%d", rec.Code)
	}
}

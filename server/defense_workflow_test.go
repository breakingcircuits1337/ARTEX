package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/defense"
)

func TestDefenseWorkflowStrictJSON(t *testing.T) {
	var input struct {
		Reason string `json:"reason"`
	}
	for _, raw := range []string{
		`{}` + `{}`,
		`{"reason":"valid explanation","unknown":"injection"}`,
		`{"reason":"a"}` + strings.Repeat(" ", 4100),
		`[]`,
	} {
		request := httptest.NewRequest(http.MethodPost, "/api/defense/responses/1/decision", strings.NewReader(raw))
		rec := httptest.NewRecorder()
		input = struct{ Reason string `json:"reason"` }{}
		if decodeDefenseWorkflow(rec, request, &input) {
			t.Errorf("accepted invalid workflow body %q", raw[:min(len(raw), 70)])
		}
		if rec.Code != http.StatusBadRequest {
			t.Errorf("invalid body returned HTTP %d", rec.Code)
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/api/defense/cases/1/triage",
		strings.NewReader(`{"reason":"reviewed recorded evidence"}`))
	rec := httptest.NewRecorder()
	if !decodeDefenseWorkflow(rec, req, &input) {
		t.Fatalf("valid workflow body rejected: %s", rec.Body.String())
	}
	if input.Reason != "reviewed recorded evidence" {
		t.Errorf("unexpected reason %q", input.Reason)
	}
}

func TestDefenseWorkflowReasonAndIDBoundaries(t *testing.T) {
	rec := httptest.NewRecorder()
	if _, ok := workflowReason(rec, "too short"); ok || rec.Code != http.StatusBadRequest {
		t.Fatal("short audit reason was accepted")
	}
	rec = httptest.NewRecorder()
	got, ok := workflowReason(rec, "   reviewed normalized security telemetry   ")
	if !ok || got != "reviewed normalized security telemetry" {
		t.Fatalf("valid reason %q %v", got, ok)
	}
	r := httptest.NewRequest(http.MethodPost, "/api/defense/cases/-1/triage", nil)
	r.SetPathValue("id", "-1")
	rec = httptest.NewRecorder()
	if _, ok := workflowID(rec, r); ok || rec.Code != http.StatusBadRequest {
		t.Fatal("negative ID accepted")
	}
}

func TestDefenseWorkflowPreviewOnly(t *testing.T) {
	t.Setenv("ARTEX_MODE", "defense")
	s := &Server{}
	// A read-only playbook catalog requires no database. The response never
	// advertises an executable action, credential, target URI, or runner.
	rec := httptest.NewRecorder()
	s.listDefensePlaybooks(rec, httptest.NewRequest(http.MethodGet, "/api/defense/playbooks", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("playbooks=%d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"execution_supported":false`) {
		t.Fatalf("unsafe playbook output: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "review_endpoint_isolation") {
		t.Fatal("missing reviewed response template")
	}
	if _, ok := defense.LookupPlaybook("shell_command"); ok {
		t.Fatal("unapproved executable template")
	}
}

func TestDefenseWorkflowsDisabledOutsideDefenseMode(t *testing.T) {
	t.Setenv("ARTEX_MODE", "pentest")
	s := &Server{}
	r := httptest.NewRequest(http.MethodGet, "/api/defense/playbooks", nil)
	rec := httptest.NewRecorder()
	s.listDefensePlaybooks(rec, r)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("mode gate=%d", rec.Code)
	}
}

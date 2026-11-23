package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const goodAIReviewFixture = `{"summary":"This unverified alert needs human confirmation from original sensor records.","findings":[{"evidence_ref":"ev1","category":"verification_gap","explanation":"Check authorized maintenance records and validate original source evidence."}]}`

// aiPreviewForTest obtains the real read-only preflight digest. This is the
// same request an operator must inspect before consenting to model egress.
func aiPreviewForTest(t *testing.T, s *Server, caseID int64) string {
    t.Helper()
    path:=fmt.Sprintf("/api/defense/cases/%d/ai-reviews/preview",caseID)
    req:=httptest.NewRequest(http.MethodGet,path,nil)
    req.SetPathValue("id",strconv.FormatInt(caseID,10))
    rec:=httptest.NewRecorder()
    s.previewDefenseAIReview(rec,req)
    if rec.Code!=http.StatusOK {t.Fatalf("AI preview=%d: %s",rec.Code,rec.Body.String())}
    var out struct {
        PacketSHA256 string `json:"packet_sha256"`
        NoModelCall bool `json:"no_model_call"`
        Packet struct{
            Schema string `json:"schema"`
            Facts []struct{Ref string `json:"ref"`} `json:"facts"`
        } `json:"packet"`
    }
    if err:=json.Unmarshal(rec.Body.Bytes(),&out);err!=nil{t.Fatal(err)}
    if len(out.PacketSHA256)!=64 || !out.NoModelCall ||
        out.Packet.Schema!="artex-redacted-evidence-v1" ||
        len(out.Packet.Facts)==0 || out.Packet.Facts[0].Ref!="ev1" {
        t.Fatalf("unsafe or incomplete preflight: %+v",out)
    }
    if rec.Header().Get("Cache-Control")!="no-store"{t.Fatal("preview response is cacheable")}
    return out.PacketSHA256
}


func TestAIReviewDisabledByDefaultAndAuthBoundary(t *testing.T) {
	t.Setenv("ARTEX_MODE", "defense")
	t.Setenv("ARTEX_DEFENSE_AI_ASSIST_ENABLED", "")
	s := &Server{jwtKey: []byte(strings.Repeat("x", 32))}
	p := "/api/defense/cases/1/ai-reviews"
	req := httptest.NewRequest(http.MethodPost, p, strings.NewReader(`{"consent_to_model":true}`))
	req.SetPathValue("id", "1")
	rec := httptest.NewRecorder()
	s.requestDefenseAIReview(rec, req)
	if rec.Code != 403 {
		t.Fatalf("opt-in failed: %d", rec.Code)
	}
	wrapped := s.requireAuth(http.HandlerFunc(s.requestDefenseAIReview))
	rec = httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatalf("anonymous access allowed: %d", rec.Code)
	}
	t.Setenv("ARTEX_MODE", "pentest")
	rec = httptest.NewRecorder()
	s.requestDefenseAIReview(rec, req)
	if rec.Code != 404 {
		t.Fatalf("AI supported in nondefense mode: %d", rec.Code)
	}
}

func TestAIReviewManualConsentGroundedHumanDecisionPG(t *testing.T) {
	t.Setenv("ARTEX_MODE", "defense")
	t.Setenv("ARTEX_DEFENSE_AI_ASSIST_ENABLED", "1")
	m := investigationTestManager(t)
	caseID, eventID := investigationTestCase(t, m, "ai-review", "low")
	var modelCalls atomic.Int32
	s := &Server{m: m, defenseAICall: func(_ context.Context, prompt string) (string, error) {
		modelCalls.Add(1)
		for _, disallowed := range []string{"2001:db8:", "phase7-ai-review", "src_ip", "dst_ip", "signature", "username", "company_id", "agent tools"} {
			if strings.Contains(prompt, disallowed) {
				t.Errorf("sensitive field in prompt %q", disallowed)
			}
		}
		if !strings.Contains(prompt, `"ref":"ev1"`) || !strings.Contains(prompt, `"relation":"alert_anchor"`) {
			t.Errorf("model was not sent minimal evidence ref: %s", prompt)
		}
		return goodAIReviewFixture, nil
	}}
	post := func(body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/api/defense/cases/"+strconv.FormatInt(caseID, 10)+"/ai-reviews", strings.NewReader(body))
		req.SetPathValue("id", strconv.FormatInt(caseID, 10))
		rec := httptest.NewRecorder()
		s.requestDefenseAIReview(rec, req)
		return rec
	}
	if rec := post(`{"consent_to_model":false}`); rec.Code != 400 {
		t.Fatalf("no-consent response: %d", rec.Code)
	}
	if modelCalls.Load() != 0 {
		t.Fatal("AI was invoked without consent")
	}
	digest:=aiPreviewForTest(t,s,caseID)
    rec := post(fmt.Sprintf(`{"consent_to_model":true,"reviewed_packet_sha256":%q}`,digest))
    if rec.Code != 200 {
		t.Fatalf("AI review request %d %s", rec.Code, rec.Body.String())
	}
	if modelCalls.Load() != 1 {
		t.Fatalf("model calls=%d want 1", modelCalls.Load())
	}
	var response struct {
		RunID int64 `json:"run_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil || response.RunID <= 0 {
		t.Fatalf("invalid advisory response: %s err=%v", rec.Body.String(), err)
	}
	var findingID int64
	if err := m.pg.QueryRow(`SELECT id FROM defense_ai_review_findings WHERE run_id=$1 AND evidence_event_id=$2`, response.RunID, eventID).
		Scan(&findingID); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var emergencyActions, deterministic int
	if err := m.pg.QueryRowContext(ctx, `SELECT count(*) FROM defense_emergency_actions WHERE event_id=$1`, eventID).
		Scan(&emergencyActions); err != nil || emergencyActions != 0 {
		t.Fatalf("AI caused containment %d %v", emergencyActions, err)
	}
	if err := m.pg.QueryRowContext(ctx, `SELECT count(*) FROM defense_investigation_findings WHERE case_id=$1`, caseID).
		Scan(&deterministic); err != nil || deterministic != 0 {
		t.Fatalf("AI polluted deterministic findings: %d %v", deterministic, err)
	}
	list := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/defense/cases/%d/ai-reviews", caseID), nil)
	request.SetPathValue("id", strconv.FormatInt(caseID, 10))
	s.listDefenseAIReviews(list, request)
	if list.Code != 200 || !strings.Contains(list.Body.String(), `"requires_human_review":true`) {
		t.Fatalf("list response %d %s", list.Code, list.Body.String())
	}
	review := func(verdict string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/defense/ai-reviews/%d/decision", findingID),
			strings.NewReader(fmt.Sprintf(`{"verdict":%q,"reason":"Analyst checked primary sensor evidence and authorized activity."}`, verdict)))
		req.SetPathValue("id", strconv.FormatInt(findingID, 10))
		rec := httptest.NewRecorder()
		s.decideDefenseAIReview(rec, req)
		return rec
	}
	if rec := review("needs_more_evidence"); rec.Code != 200 {
		t.Fatalf("human verdict %d: %s", rec.Code, rec.Body.String())
	}
	if rec := review("supported"); rec.Code != 409 {
		t.Fatalf("second immutable verdict accepted: %d", rec.Code)
	}
	_, err := m.pg.ExecContext(ctx, `UPDATE defense_ai_review_findings SET explanation='overwrite' WHERE id=$1`, findingID)
	if err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("AI finding was editable: %v", err)
	}
	_, err = m.pg.ExecContext(ctx, `DELETE FROM defense_ai_review_decisions WHERE finding_id=$1`, findingID)
	if err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("human verdict could be deleted: %v", err)
	}
	var audited int
	if err := m.pg.QueryRowContext(ctx, `SELECT count(*) FROM defense_ai_review_audit WHERE run_id=$1`, response.RunID).Scan(&audited); err != nil || audited != 3 {
		t.Fatalf("missing audit rows %d / %v", audited, err)
	}
}

func TestAIReviewRejectsFabricatedCitationAndQuotaPG(t *testing.T) {
	t.Setenv("ARTEX_MODE", "defense")
	t.Setenv("ARTEX_DEFENSE_AI_ASSIST_ENABLED", "1")
	m := investigationTestManager(t)
	caseID, _ := investigationTestCase(t, m, "ai-invalid", "medium")
	var calls atomic.Int32
	s := &Server{m: m, defenseAICall: func(context.Context, string) (string, error) {
		calls.Add(1)
		return strings.Replace(goodAIReviewFixture, "ev1", "ev999", 1), nil
	}}
	digest:=aiPreviewForTest(t,s,caseID)
    send := func() *httptest.ResponseRecorder {
        t.Helper()
        req := httptest.NewRequest(http.MethodPost,fmt.Sprintf("/api/defense/cases/%d/ai-reviews",caseID),
            strings.NewReader(fmt.Sprintf(`{"consent_to_model":true,"reviewed_packet_sha256":%q}`,digest)))
		req.SetPathValue("id", strconv.FormatInt(caseID, 10))
		w := httptest.NewRecorder()
		s.requestDefenseAIReview(w, req)
		return w
	}
	w := send()
	if w.Code != 502 {
		t.Fatalf("fabricated citation saved: %d %s", w.Code, w.Body.String())
	}
	var findings int
	if err := m.pg.QueryRow(`SELECT count(*) FROM defense_ai_review_findings WHERE case_id=$1`, caseID).Scan(&findings); err != nil || findings != 0 {
		t.Fatalf("fabricated citation persisted: %d %v", findings, err)
	}
	s.defenseAICall = func(context.Context, string) (string, error) { calls.Add(1); return goodAIReviewFixture, nil }
	for i := 0; i < 2; i++ {
		if w := send(); w.Code != 200 {
			t.Fatalf("manual retry %d: %d %s", i, w.Code, w.Body.String())
		}
	}
	if w := send(); w.Code != 429 {
		t.Fatalf("quota should block fourth request: %d %s", w.Code, w.Body.String())
	}
	if calls.Load() != 3 {
		t.Fatalf("quota did not block egress: calls=%d", calls.Load())
	}
}

func TestAIReviewCannotInsertUnscopedForeignEvidencePG(t *testing.T) {
	t.Setenv("ARTEX_MODE", "defense")
	m := investigationTestManager(t)
	one, oneEvent := investigationTestCase(t, m, "ai-scope-one", "low")
	_, otherEvent := investigationTestCase(t, m, "ai-scope-other", "low")
	var id int64
	hash := strings.Repeat("a", 64)
	if err := m.pg.QueryRow(`INSERT INTO defense_ai_review_runs(case_id,packet_sha256,status)
        VALUES($1,$2,'completed') RETURNING id`, one, hash).Scan(&id); err != nil {
		t.Fatal(err)
	}
	_, err := m.pg.Exec(`INSERT INTO defense_ai_review_findings(run_id,case_id,evidence_event_id,category,explanation)
        VALUES($1,$2,$3,'verification_gap','This is a fabricated cross-case model citation.')`, id, one, otherEvent)
	if err == nil {
		t.Fatal("foreign case evidence inserted into AI finding")
	}
	_, err = m.pg.Exec(`INSERT INTO defense_ai_review_findings(run_id,case_id,evidence_event_id,category,explanation)
        VALUES($1,$2,$3,'verification_gap','This is the actual case event for review.')`, id, one, oneEvent)
	if err != nil {
		t.Fatalf("valid anchor observation rejected: %v", err)
	}
}


func TestAIReviewPreviewConsentAndEvidenceDriftPG(t *testing.T){
    t.Setenv("ARTEX_MODE","defense")
    t.Setenv("ARTEX_DEFENSE_AI_ASSIST_ENABLED","1")
    m:=investigationTestManager(t)
    caseID,eventID:=investigationTestCase(t,m,"preview-stale","low")
    var calls atomic.Int32
    s:=&Server{m:m,defenseAICall:func(_ context.Context, prompt string)(string,error){
        calls.Add(1)
        if strings.Contains(prompt,"src_ip") || strings.Contains(prompt,"company_id") ||
            strings.Contains(prompt,"host") || strings.Contains(prompt,"2001:db8"){
            t.Errorf("sensitive values were sent to provider: %s",prompt)
        }
        return goodAIReviewFixture,nil
    }}
    original:=aiPreviewForTest(t,s,caseID)
    var before int
    if err:=m.pg.QueryRow(`SELECT count(*) FROM defense_ai_review_runs WHERE case_id=$1`,caseID).Scan(&before);err!=nil || before!=0{
        t.Fatalf("read-only preflight created reservation: %d %v",before,err)
    }
    request:=func(digest string)*httptest.ResponseRecorder{
        t.Helper()
        p:=fmt.Sprintf("/api/defense/cases/%d/ai-reviews",caseID)
        req:=httptest.NewRequest(http.MethodPost,p,strings.NewReader(
            fmt.Sprintf(`{"consent_to_model":true,"reviewed_packet_sha256":%q}`,digest)))
        req.SetPathValue("id",strconv.FormatInt(caseID,10))
        rec:=httptest.NewRecorder()
        s.requestDefenseAIReview(rec,req)
        return rec
    }
    if rec:=request("");rec.Code!=400{t.Fatalf("missing preview digest accepted: %d",rec.Code)}
    if rec:=request(strings.Repeat("f",64));rec.Code!=409{t.Fatalf("forged preview accepted: %d",rec.Code)}
    if calls.Load()!=0{t.Fatal("model called before verified consent")}
    var alertID int64
    if err:=m.pg.QueryRow(`SELECT alert_id FROM defense_cases WHERE id=$1`,caseID).Scan(&alertID);err!=nil{t.Fatal(err)}
    if _,err:=m.pg.Exec(`UPDATE defense_alerts SET severity='high' WHERE id=$1`,alertID);err!=nil{t.Fatal(err)}
    if rec:=request(original);rec.Code!=409{t.Fatalf("stale packet hash accepted: %d %s",rec.Code,rec.Body.String())}
    if calls.Load()!=0{t.Fatal("model called on changed evidence")}
    fresh:=aiPreviewForTest(t,s,caseID)
    if fresh==original{t.Fatal("severity change did not change evidence digest")}
    rec:=request(fresh)
    if rec.Code!=200{t.Fatalf("fresh consent rejected: %d %s",rec.Code,rec.Body.String())}
    if calls.Load()!=1{t.Fatalf("expected one model call, got %d",calls.Load())}
    var runID int64
    if err:=m.pg.QueryRow(`SELECT id FROM defense_ai_review_runs WHERE case_id=$1`,caseID).Scan(&runID);err!=nil{t.Fatal(err)}
    var recorded string
    if err:=m.pg.QueryRow(`SELECT packet_sha256 FROM defense_ai_review_runs WHERE id=$1`,runID).Scan(&recorded);err!=nil{t.Fatal(err)}
    if recorded!=fresh{t.Fatalf("stored consent packet hash mismatch: %q",recorded)}
    var caused int
    if err:=m.pg.QueryRow(`SELECT count(*) FROM defense_emergency_actions WHERE event_id=$1`,eventID).Scan(&caused);err!=nil || caused!=0{
        t.Fatalf("consented AI review triggered enforcement: %d %v",caused,err)
    }
}
func TestAIReviewPreviewDisabledAndAdminBoundaries(t *testing.T){
    t.Setenv("ARTEX_MODE","defense")
    t.Setenv("ARTEX_DEFENSE_AI_ASSIST_ENABLED","")
    s:=&Server{jwtKey:[]byte(strings.Repeat("x",32))}
    path:="/api/defense/cases/1/ai-reviews/preview"
    handler:=http.HandlerFunc(s.previewDefenseAIReview)
    req:=httptest.NewRequest(http.MethodGet,path,nil)
    req.SetPathValue("id","1")
    rec:=httptest.NewRecorder()
    handler.ServeHTTP(rec,req)
    if rec.Code!=403{t.Fatalf("disabled preview: %d",rec.Code)}
    t.Setenv("ARTEX_DEFENSE_AI_ASSIST_ENABLED","1")
    rec=httptest.NewRecorder()
    s.requireAuth(handler).ServeHTTP(rec,req)
    if rec.Code!=401{t.Fatalf("anonymous preview accepted: %d",rec.Code)}
    req.Header.Set("Authorization","Collector bogus-secret")
    rec=httptest.NewRecorder()
    s.requireAuth(handler).ServeHTTP(rec,req)
    if rec.Code!=401{t.Fatalf("sensor credential accepted: %d",rec.Code)}
    t.Setenv("ARTEX_MODE","pentest")
    rec=httptest.NewRecorder()
    handler.ServeHTTP(rec,req)
    if rec.Code!=404{t.Fatalf("preview enabled in pentest: %d",rec.Code)}
}

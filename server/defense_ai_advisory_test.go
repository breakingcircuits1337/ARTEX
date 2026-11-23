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

const goodAIReviewFixture=`{"summary":"This unverified alert needs human confirmation from original sensor records.","findings":[{"evidence_ref":"ev1","category":"verification_gap","explanation":"Check authorized maintenance records and validate original source evidence."}]}`

func TestAIReviewDisabledByDefaultAndAuthBoundary(t *testing.T){
    t.Setenv("ARTEX_MODE","defense")
    t.Setenv("ARTEX_DEFENSE_AI_ASSIST_ENABLED","")
    s:=&Server{jwtKey:[]byte(strings.Repeat("x",32))}
    p:="/api/defense/cases/1/ai-reviews"
    req:=httptest.NewRequest(http.MethodPost,p,strings.NewReader(`{"consent_to_model":true}`))
    req.SetPathValue("id","1")
    rec:=httptest.NewRecorder()
    s.requestDefenseAIReview(rec,req)
    if rec.Code!=403 {t.Fatalf("opt-in failed: %d",rec.Code)}
    wrapped:=s.requireAuth(http.HandlerFunc(s.requestDefenseAIReview))
    rec=httptest.NewRecorder()
    wrapped.ServeHTTP(rec,req)
    if rec.Code!=401{t.Fatalf("anonymous access allowed: %d",rec.Code)}
    t.Setenv("ARTEX_MODE","pentest")
    rec=httptest.NewRecorder()
    s.requestDefenseAIReview(rec,req)
    if rec.Code!=404{t.Fatalf("AI supported in nondefense mode: %d",rec.Code)}
}

func TestAIReviewManualConsentGroundedHumanDecisionPG(t *testing.T){
    t.Setenv("ARTEX_MODE","defense")
    t.Setenv("ARTEX_DEFENSE_AI_ASSIST_ENABLED","1")
    m:=investigationTestManager(t)
    caseID,eventID:=investigationTestCase(t,m,"ai-review","low")
    var modelCalls atomic.Int32
    s:=&Server{m:m,defenseAICall:func(_ context.Context,prompt string)(string,error){
        modelCalls.Add(1)
        for _,disallowed:=range []string{"2001:db8:", "phase7-ai-review","src_ip","dst_ip","signature","username","company_id","agent tools"}{
            if strings.Contains(prompt,disallowed){t.Errorf("sensitive field in prompt %q",disallowed)}
        }
        if !strings.Contains(prompt,`"ref":"ev1"`) || !strings.Contains(prompt,`"relation":"alert_anchor"`){
            t.Errorf("model was not sent minimal evidence ref: %s",prompt)
        }
        return goodAIReviewFixture,nil
    }}
    post:=func(body string)*httptest.ResponseRecorder{
        t.Helper()
        req:=httptest.NewRequest(http.MethodPost,"/api/defense/cases/"+strconv.FormatInt(caseID,10)+"/ai-reviews",strings.NewReader(body))
        req.SetPathValue("id",strconv.FormatInt(caseID,10))
        rec:=httptest.NewRecorder()
        s.requestDefenseAIReview(rec,req)
        return rec
    }
    if rec:=post(`{"consent_to_model":false}`);rec.Code!=400{t.Fatalf("no-consent response: %d",rec.Code)}
    if modelCalls.Load()!=0{t.Fatal("AI was invoked without consent")}
    rec:=post(`{"consent_to_model":true}`)
    if rec.Code!=200{t.Fatalf("AI review request %d %s",rec.Code,rec.Body.String())}
    if modelCalls.Load()!=1{t.Fatalf("model calls=%d want 1",modelCalls.Load())}
    var response struct{RunID int64 `json:"run_id"`}
    if err:=json.Unmarshal(rec.Body.Bytes(),&response);err!=nil || response.RunID<=0{
        t.Fatalf("invalid advisory response: %s err=%v",rec.Body.String(),err)
    }
    var findingID int64
    if err:=m.pg.QueryRow(`SELECT id FROM defense_ai_review_findings WHERE run_id=$1 AND evidence_event_id=$2`,response.RunID,eventID).
        Scan(&findingID);err!=nil{t.Fatal(err)}
    ctx,cancel:=context.WithTimeout(context.Background(),10*time.Second)
    defer cancel()
    var emergencyActions,deterministic int
    if err:=m.pg.QueryRowContext(ctx,`SELECT count(*) FROM defense_emergency_actions WHERE event_id=$1`,eventID).
        Scan(&emergencyActions);err!=nil || emergencyActions!=0{t.Fatalf("AI caused containment %d %v",emergencyActions,err)}
    if err:=m.pg.QueryRowContext(ctx,`SELECT count(*) FROM defense_investigation_findings WHERE case_id=$1`,caseID).
        Scan(&deterministic);err!=nil || deterministic!=0{t.Fatalf("AI polluted deterministic findings: %d %v",deterministic,err)}
    list:=httptest.NewRecorder()
    request:=httptest.NewRequest(http.MethodGet,fmt.Sprintf("/api/defense/cases/%d/ai-reviews",caseID),nil)
    request.SetPathValue("id",strconv.FormatInt(caseID,10))
    s.listDefenseAIReviews(list,request)
    if list.Code!=200 || !strings.Contains(list.Body.String(),`"requires_human_review":true`) {
        t.Fatalf("list response %d %s",list.Code,list.Body.String())
    }
    review:=func(verdict string)*httptest.ResponseRecorder{
        t.Helper()
        req:=httptest.NewRequest(http.MethodPost,fmt.Sprintf("/api/defense/ai-reviews/%d/decision",findingID),
            strings.NewReader(fmt.Sprintf(`{"verdict":%q,"reason":"Analyst checked primary sensor evidence and authorized activity."}`,verdict)))
        req.SetPathValue("id",strconv.FormatInt(findingID,10))
        rec:=httptest.NewRecorder()
        s.decideDefenseAIReview(rec,req)
        return rec
    }
    if rec:=review("needs_more_evidence");rec.Code!=200{t.Fatalf("human verdict %d: %s",rec.Code,rec.Body.String())}
    if rec:=review("supported");rec.Code!=409{t.Fatalf("second immutable verdict accepted: %d",rec.Code)}
    _,err:=m.pg.ExecContext(ctx,`UPDATE defense_ai_review_findings SET explanation='overwrite' WHERE id=$1`,findingID)
    if err==nil || !strings.Contains(err.Error(),"append-only"){t.Fatalf("AI finding was editable: %v",err)}
    _,err=m.pg.ExecContext(ctx,`DELETE FROM defense_ai_review_decisions WHERE finding_id=$1`,findingID)
    if err==nil || !strings.Contains(err.Error(),"append-only"){t.Fatalf("human verdict could be deleted: %v",err)}
    var audited int
    if err:=m.pg.QueryRowContext(ctx,`SELECT count(*) FROM defense_ai_review_audit WHERE run_id=$1`,response.RunID).Scan(&audited);err!=nil || audited!=3{t.Fatalf("missing audit rows %d / %v",audited,err)}
}

func TestAIReviewRejectsFabricatedCitationAndQuotaPG(t *testing.T){
    t.Setenv("ARTEX_MODE","defense")
    t.Setenv("ARTEX_DEFENSE_AI_ASSIST_ENABLED","1")
    m:=investigationTestManager(t)
    caseID,_:=investigationTestCase(t,m,"ai-invalid","medium")
    var calls atomic.Int32
    s:=&Server{m:m,defenseAICall:func(context.Context,string)(string,error){
        calls.Add(1)
        return strings.Replace(goodAIReviewFixture,"ev1","ev999",1),nil
    }}
    send:=func()*httptest.ResponseRecorder{
        t.Helper()
        req:=httptest.NewRequest(http.MethodPost,fmt.Sprintf("/api/defense/cases/%d/ai-reviews",caseID),
            strings.NewReader(`{"consent_to_model":true}`))
        req.SetPathValue("id",strconv.FormatInt(caseID,10))
        w:=httptest.NewRecorder();s.requestDefenseAIReview(w,req)
        return w
    }
    w:=send()
    if w.Code!=502{t.Fatalf("fabricated citation saved: %d %s",w.Code,w.Body.String())}
    var findings int
    if err:=m.pg.QueryRow(`SELECT count(*) FROM defense_ai_review_findings WHERE case_id=$1`,caseID).Scan(&findings);err!=nil || findings!=0{
        t.Fatalf("fabricated citation persisted: %d %v",findings,err)
    }
    s.defenseAICall=func(context.Context,string)(string,error){calls.Add(1);return goodAIReviewFixture,nil}
    for i:=0;i<2;i++{if w:=send();w.Code!=200{t.Fatalf("manual retry %d: %d %s",i,w.Code,w.Body.String())}}
    if w:=send();w.Code!=429{t.Fatalf("quota should block fourth request: %d %s",w.Code,w.Body.String())}
    if calls.Load()!=3{t.Fatalf("quota did not block egress: calls=%d",calls.Load())}
}

func TestAIReviewCannotInsertUnscopedForeignEvidencePG(t *testing.T){
    t.Setenv("ARTEX_MODE","defense")
    m:=investigationTestManager(t)
    one,oneEvent:=investigationTestCase(t,m,"ai-scope-one","low")
    _,otherEvent:=investigationTestCase(t,m,"ai-scope-other","low")
    var id int64
    hash:=strings.Repeat("a",64)
    if err:=m.pg.QueryRow(`INSERT INTO defense_ai_review_runs(case_id,packet_sha256,status)
        VALUES($1,$2,'completed') RETURNING id`,one,hash).Scan(&id);err!=nil{t.Fatal(err)}
    _,err:=m.pg.Exec(`INSERT INTO defense_ai_review_findings(run_id,case_id,evidence_event_id,category,explanation)
        VALUES($1,$2,$3,'verification_gap','This is a fabricated cross-case model citation.')`,id,one,otherEvent)
    if err==nil{t.Fatal("foreign case evidence inserted into AI finding")}
    _,err=m.pg.Exec(`INSERT INTO defense_ai_review_findings(run_id,case_id,evidence_event_id,category,explanation)
        VALUES($1,$2,$3,'verification_gap','This is the actual case event for review.')`,id,one,oneEvent)
    if err!=nil{t.Fatalf("valid anchor observation rejected: %v",err)}
}

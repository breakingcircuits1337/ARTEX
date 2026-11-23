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

func TestPR12SigmaAlertAndATTACKHintPG(t *testing.T) {
    t.Setenv("ARTEX_MODE","defense")
    m:=tenantTestManager(t)
    s:=&Server{m:m}
    name:=fmt.Sprintf("pr12-sigma-%d",time.Now().UnixNano())
    var company int64
    if err:=m.pg.QueryRow(`INSERT INTO companies(name,nkey) VALUES($1,$1) RETURNING id`,name).Scan(&company);err!=nil{
        t.Fatal(err)
    }
    raw:=fmt.Sprintf(`{"source":"generic","company_id":%d,"events":[
      {"event_id":"%s","kind":"endpoint","action":"security_agent_disabled"}]}`,company,name)
    rec:=httptest.NewRecorder()
    s.ingestDefenseEvents(rec,httptest.NewRequest(http.MethodPost,"/api/defense/events",strings.NewReader(raw)))
    if rec.Code!=200{t.Fatalf("ingest status=%d body=%s",rec.Code,rec.Body.String())}
    var ack struct {Ingested int `json:"ingested"`; AlertsCreated int `json:"alerts_created"`}
    if err:=json.Unmarshal(rec.Body.Bytes(),&ack);err!=nil{t.Fatal(err)}
    if ack.Ingested!=1 || ack.AlertsCreated!=1{t.Fatalf("unexpected ack %+v",ack)}
    var alertID,eventID int64
    if err:=m.pg.QueryRow(`SELECT a.id,a.event_id FROM defense_alerts a
        JOIN defense_events e ON e.id=a.event_id
        WHERE a.rule_id=$1 AND e.external_id=$2 AND e.company_id=$3`,
        "sigma_9ab1e612-46ba-40bd-91d5-31d4ee36f001",name,company).
        Scan(&alertID,&eventID);err!=nil{t.Fatal(err)}
    ctx,cancel:=context.WithTimeout(context.Background(),10*time.Second)
    defer cancel()
    tx,err:=m.pg.BeginTx(ctx,nil)
    if err!=nil{t.Fatal(err)}
    defer tx.Rollback()
    var caseID int64
    if err:=tx.QueryRowContext(ctx,`INSERT INTO defense_cases(alert_id)
        VALUES($1) RETURNING id`,alertID).Scan(&caseID);err!=nil{t.Fatal(err)}
    if _,err:=correlateDefenseCase(ctx,tx,caseID,"correlator");err!=nil{t.Fatal(err)}
    var technique,tactic,origin string
    var confidence int
    if err:=tx.QueryRowContext(ctx,`SELECT technique_id,tactic_id,mapping_source,confidence
        FROM defense_case_techniques WHERE case_id=$1 AND evidence_event_id=$2`,
        caseID,eventID).Scan(&technique,&tactic,&origin,&confidence);err!=nil{t.Fatal(err)}
    if technique!="T1685" || tactic!="TA0112" || origin!="rule_hint" || confidence!=35 {
        t.Fatalf("unreviewed ATT&CK mapping: %s %s %s %d",technique,tactic,origin,confidence)
    }
}

func TestPR12PasswordGuessingScopedIdempotentPG(t *testing.T) {
    t.Setenv("ARTEX_MODE","defense")
    m:=tenantTestManager(t)
    s:=&Server{m:m}
    name:=fmt.Sprintf("pr12-guess-%d",time.Now().UnixNano())
    newCompany:=func(suffix string)int64{
        t.Helper()
        var id int64
        value:=name+"-"+suffix
        if err:=m.pg.QueryRow(`INSERT INTO companies(name,nkey)
            VALUES($1,$1) RETURNING id`,value).Scan(&id);err!=nil{t.Fatal(err)}
        return id
    }
    a,b:=newCompany("a"),newCompany("b")
    makeBatch:=func(company int64,quantity int,tag string)string{
        t.Helper()
        events:=make([]map[string]string,0,quantity)
        for i:=0;i<quantity;i++{
            events=append(events,map[string]string{
                "event_id":fmt.Sprintf("%s-%s-%d",name,tag,i),
                "kind":"authentication","outcome":"failure",
                "src_ip":"203.0.113.234","username":"TestOperator",
            })
        }
        body,err:=json.Marshal(map[string]any{"source":"generic","company_id":company,"events":events})
        if err!=nil{t.Fatal(err)}
        return string(body)
    }
    submit:=func(body string) *httptest.ResponseRecorder{
        t.Helper()
        rec:=httptest.NewRecorder()
        s.ingestDefenseEvents(rec,httptest.NewRequest(http.MethodPost,"/api/defense/events",strings.NewReader(body)))
        if rec.Code!=200{t.Fatalf("failed ingest: %d %s",rec.Code,rec.Body.String())}
        return rec
    }
    // Unrelated tenant failures, even with the same account and IP, do not
    // contribute to company A's threshold.
    submit(makeBatch(b,7,"other"))
    submit(makeBatch(a,7,"first"))
    var count int
    if err:=m.pg.QueryRow(`SELECT count(*) FROM defense_alerts a JOIN defense_events e ON e.id=a.event_id
        WHERE a.rule_id='auth_guess_burst_v1' AND e.company_id IN ($1,$2)`,a,b).Scan(&count);err!=nil{t.Fatal(err)}
    if count!=0{t.Fatal("cross-company failure aggregate was accepted")}
    last:=makeBatch(a,1,"eighth")
    submit(last)
    submit(last) // replay must not add a second alert or event
    if err:=m.pg.QueryRow(`SELECT count(*) FROM defense_alerts a JOIN defense_events e ON e.id=a.event_id
        WHERE a.rule_id='auth_guess_burst_v1' AND e.company_id=$1`,a).Scan(&count);err!=nil{t.Fatal(err)}
    if count!=1{t.Fatalf("guessing alert count=%d, want 1",count)}
    if err:=m.pg.QueryRow(`SELECT count(*) FROM defense_alerts a JOIN defense_events e ON e.id=a.event_id
        WHERE a.rule_id='auth_guess_burst_v1' AND e.company_id=$1`,b).Scan(&count);err!=nil{t.Fatal(err)}
    if count!=0{t.Fatal("independent company generated guessing alert")}
    if err:=m.pg.QueryRow(`SELECT count(*) FROM defense_events WHERE company_id=$1
        AND source='generic' AND outcome='failure'`,a).Scan(&count);err!=nil{t.Fatal(err)}
    if count!=8{t.Fatalf("replay duplicated guessed failures: %d",count)}
}

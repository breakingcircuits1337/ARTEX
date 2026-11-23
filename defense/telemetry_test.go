package defense

import (
 "encoding/json"
 "strings"
 "testing"
 "time"
)

func TestNormalizeSuricataAndDedupKey(t *testing.T){
 now:=time.Date(2026,11,23,12,0,0,0,time.UTC)
 raw:=json.RawMessage(`{"timestamp":"2026-11-23T11:59:00Z","event_type":"alert","src_ip":"10.0.0.1","dest_ip":"10.0.0.2","alert":{"signature":"Suspicious DNS","severity":1}}`)
 e,err:=NormalizeEvent("suricata",raw,now)
 if err!=nil {t.Fatal(err)}
 if e.Kind!="network"||!e.VendorAlert||e.Severity!=9||e.Signature!="Suspicious DNS"||!strings.HasPrefix(e.ExternalID,"sha256:"){t.Fatalf("bad event %+v",e)}
 if hits:=EvaluateEvent(e);len(hits)!=1||hits[0].Severity!="high"{t.Fatalf("bad hits %+v",hits)}
 e2,err:=NormalizeEvent("suricata",raw,now);if err!=nil||e.ExternalID!=e2.ExternalID{t.Fatal("idempotency mismatch")}
}

func TestNormalizeWazuhAndGeneric(t *testing.T){
 now:=time.Now()
 a,err:=NormalizeEvent("wazuh",json.RawMessage(`{"id":"abc-1","rule":{"level":12,"description":"Suspicious login","groups":["authentication_failed"]},"agent":{"name":"host.local"},"data":{"srcip":"192.0.2.10","srcuser":"operator"},"timestamp":"2026-11-22T12:00:00Z"}`),now)
 if err!=nil||!a.VendorAlert||a.Kind!="authentication"||a.Host!="host.local"{t.Fatalf("%+v err=%v",a,err)}
 b,err:=NormalizeEvent("generic",json.RawMessage(`{"event_id":"evt-7","kind":"authentication","outcome":"failure","src_ip":"192.0.2.11","username":"someone"}`),now)
 if err!=nil||b.Outcome!="failure"||len(EvaluateEvent(b))!=0{t.Fatalf("%+v err=%v",b,err)}
}

func TestNormalizeRejectsInvalidInput(t *testing.T) {
 now:=time.Now()
 for _,raw:=range []string{
  `{"kind":"other","src_ip":"not-an-ip"}`,
  `{"kind":"other","timestamp":"nonsense"}`,
  `{"kind":"other","signature":"`+strings.Repeat("a",513)+`"}`,
  `{"kind":"unknown"}`,
  `[]`,
 } {
  if _,err:=NormalizeEvent("generic",json.RawMessage(raw),now);err==nil {t.Errorf("accepted invalid %s",raw)}
 }
 if _,err:=NormalizeEvent("other",json.RawMessage(`{"kind":"other"}`),now);err==nil{t.Fatal("accepted unknown source")}
}

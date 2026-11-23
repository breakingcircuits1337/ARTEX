package defense

import (
 "bytes"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "net"
 "strings"
 "time"
)

// SecurityEvent is a bounded, vendor-neutral projection. Raw event payloads,
// credentials, tokens and request bodies are intentionally never persisted.
type SecurityEvent struct {
 Source string `json:"source"`
 ExternalID string `json:"external_id"`
 ObservedAt time.Time `json:"observed_at"`
 Kind string `json:"kind"`
 Outcome string `json:"outcome,omitempty"`
 Action string `json:"action,omitempty"`
 SrcIP string `json:"src_ip,omitempty"`
 DstIP string `json:"dst_ip,omitempty"`
 Host string `json:"host,omitempty"`
 Username string `json:"username,omitempty"`
 Signature string `json:"signature,omitempty"`
 Severity int `json:"severity"`
 VendorAlert bool `json:"vendor_alert"`
}

// String fields are treated as untrusted, and bounded before database insertion.
func field(obj map[string]any, path ...string) string {
 var v any = obj
 for _, p := range path {
  m, ok := v.(map[string]any); if !ok { return "" }
  v=m[p]
 }
 switch n:=v.(type) {
 case string: return strings.TrimSpace(n)
 case json.Number: return n.String()
 default: return ""
 }
}
func first(values ...string) string { for _,v:=range values { if v!="" {return v} }; return "" }
func nestedNumber(m map[string]any, path ...string) int {
 var n int
 fmt.Sscanf(field(m,path...), "%d", &n)
 return n
}
func bounded(label,value string,max int) (string,error) {
 if len(value)>max {return "",fmt.Errorf("%s exceeds %d bytes",label,max)}
 for _,c:=range value {if c<32 {return "",fmt.Errorf("%s contains control characters",label)}}
 return value,nil
}
func normIP(s string) (string,error) {
 if s=="" {return "",nil}
 ip:=net.ParseIP(s);if ip==nil {return "",fmt.Errorf("invalid IP address")}
 return ip.String(),nil
}
func validKind(s string) bool {return s=="authentication"||s=="network"||s=="endpoint"||s=="other"}
func validOutcome(s string) bool {return s==""||s=="success"||s=="failure"||s=="unknown"}
func classify(m map[string]any, source string) string {
 if source=="suricata" {return "network"}
 if source=="wazuh" {
  for _,group:=range []string{"authentication_failed","authentication_success","authentication","pam","sshd"} {
   gs,ok:=m["rule"].(map[string]any);if !ok {break}
   a,ok:=gs["groups"].([]any);if !ok {break}
   for _,v:=range a {if v==group {return "authentication"}}
  }
  return "endpoint"
 }
 if source=="ocsf" {
  switch nestedNumber(m,"category_uid") {case 3:return "network";case 1:return "authentication"}
  return "other"
 }
 return strings.ToLower(field(m,"kind"))
}
func status(m map[string]any, source string) string {
 v:=strings.ToLower(first(field(m,"outcome"),field(m,"status"),field(m,"data","status")))
 switch v {case "failed","failure","denied","error","blocked":return "failure";case "success","succeeded","allowed","ok":return "success";case "","unknown":return "";default:return "unknown"}
}

// NormalizeEvent accepts a Suricata EVE, Wazuh alert, generic normalized event,
// or a limited OCSF-style projection. It never executes event-supplied content.
func NormalizeEvent(source string, raw json.RawMessage, now time.Time) (SecurityEvent,error) {
 e:=SecurityEvent{Source:strings.ToLower(strings.TrimSpace(source))}
 switch e.Source {case "suricata","wazuh","generic","ocsf":default:return e,errors.New("unsupported source")}
 if len(raw)==0||len(raw)>128<<10 {return e,errors.New("event must be 1..131072 bytes")}
 dec:=json.NewDecoder(bytes.NewReader(raw));dec.UseNumber()
 var m map[string]any
 if err:=dec.Decode(&m);err!=nil||m==nil {return e,errors.New("event must be a JSON object")}
 var trailing any;if dec.Decode(&trailing)!=nil && !errors.Is(nil,nil) {} // only one JSON object is accepted by JSON Unmarshal below
 if !json.Valid(raw) {return e,errors.New("invalid event JSON")}
 normalized,_:=json.Marshal(m)
 e.ExternalID=first(field(m,"event_id"),field(m,"id"),field(m,"metadata","uid"))
 if e.ExternalID=="" {
  sum:=sha256.Sum256(normalized)
  e.ExternalID="sha256:"+hex.EncodeToString(sum[:])
 }
 ts:=first(field(m,"timestamp"),field(m,"time"),field(m,"time_dt"))
 if ts=="" {e.ObservedAt=now.UTC()} else {
  t,err:=time.Parse(time.RFC3339Nano,ts)
  if err!=nil {return e,errors.New("timestamp must be RFC3339")}
  if t.After(now.Add(24*time.Hour)) {return e,errors.New("timestamp too far in the future")}
  e.ObservedAt=t.UTC()
 }
 e.Kind=classify(m,e.Source)
 if !validKind(e.Kind) {return e,errors.New("unsupported kind")}
 e.Outcome=status(m,e.Source)
 if !validOutcome(e.Outcome) {return e,errors.New("invalid outcome")}
 e.Action=first(field(m,"action"),field(m,"event_type"),field(m,"data","action"))
 e.SrcIP=first(field(m,"src_ip"),field(m,"source_ip"),field(m,"data","srcip"),field(m,"src_endpoint","ip"))
 e.DstIP=first(field(m,"dest_ip"),field(m,"dst_ip"),field(m,"data","dstip"),field(m,"dst_endpoint","ip"))
 e.Host=strings.ToLower(strings.TrimSuffix(first(field(m,"host"),field(m,"hostname"),field(m,"agent","name"),field(m,"device","hostname")),"."))
 e.Username=first(field(m,"username"),field(m,"user","name"),field(m,"data","srcuser"),field(m,"data","dstuser"))
 e.Signature=first(field(m,"signature"),field(m,"alert","signature"),field(m,"rule","description"),field(m,"message"))
 e.Severity=nestedNumber(m,"severity")
 switch e.Source {
 case "suricata":
  if e.Action=="alert" {
   e.VendorAlert=true
   switch nestedNumber(m,"alert","severity") {case 1:e.Severity=9;case 2:e.Severity=7;case 3:e.Severity=5;default:e.Severity=3}
  }
 case "wazuh":
  level:=nestedNumber(m,"rule","level")
  if level>=10 {e.VendorAlert=true}
  e.Severity=level*10/15
 case "ocsf":
  e.Severity=nestedNumber(m,"severity_id")*2
 }
 if e.Severity<0||e.Severity>10{return e,errors.New("severity out of bounds (0..10)")}
 var err error
 if e.ExternalID,err=bounded("external_id",e.ExternalID,128);err!=nil{return e,err}
 if e.SrcIP,err=normIP(e.SrcIP);err!=nil{return e,err}
 if e.DstIP,err=normIP(e.DstIP);err!=nil{return e,err}
 for _,entry:=range []struct{label,val string;max int}{
  {"host",e.Host,255},{"username",e.Username,256},{"signature",e.Signature,512},{"action",e.Action,128},
 } {
  if _,err=bounded(entry.label,entry.val,entry.max);err!=nil{return e,err}
 }
 return e,nil
}

// RuleHit is a deterministic signal, not a verified security incident.
type RuleHit struct {RuleID,Title,Severity,Summary string}
func EvaluateEvent(e SecurityEvent) []RuleHit {
 if !e.VendorAlert || e.Signature=="" {return nil}
 severity:="medium";if e.Severity>=8 {severity="high"}
 return []RuleHit{{RuleID:"vendor_alert_v1",Title:"Upstream security alert",Severity:severity,Summary:"Alert from "+e.Source+": "+e.Signature}}
}

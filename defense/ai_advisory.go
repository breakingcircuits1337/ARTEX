// Package defense keeps the deterministic investigator independent from LLMs.
// This file only validates bounded, untrusted, *advisory* model results.
package defense

import (
    "bytes"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "strings"
    "unicode"
    "unicode/utf8"
)

type AIReviewFact struct {
    Ref string `json:"ref"`
    Source string `json:"source"`
    Kind string `json:"kind"`
    Relation string `json:"relation"`
    LinkConfidence int `json:"link_confidence"`
}
type AIReviewPacket struct {
    Schema string `json:"schema"`
    AlertSeverity string `json:"alert_severity"`
    Facts []AIReviewFact `json:"facts"`
    Interpretation string `json:"interpretation"`
}
type AIAdviceFinding struct {
    EvidenceRef string `json:"evidence_ref"`
    Category string `json:"category"`
    Explanation string `json:"explanation"`
}
type AIAdvice struct {
    Summary string `json:"summary"`
    Findings []AIAdviceFinding `json:"findings"`
}
const MaxAIReviewFacts=12
const MaxAIAdviceBytes=4096

// The prompt contains only allowlisted categorical fields and ephemeral
// evidence references, not raw events, IPs, hostnames, usernames, signatures,
// company identifiers, case identifiers, credentials or free-text sensor data.
func ValidateAIReviewPacket(packet AIReviewPacket) error {
    if packet.Schema!="artex-redacted-evidence-v1" || len(packet.Facts)<1 ||
        len(packet.Facts)>MaxAIReviewFacts {return errors.New("invalid AI evidence packet")}
    switch packet.AlertSeverity {
    case "low","medium","high","critical":
    default: return errors.New("invalid AI alert severity")
    }
    if packet.Interpretation!="Unverified sensor records; linkage confidence is not compromise probability." {
        return errors.New("unsafe AI packet interpretation")
    }
    seen:=map[string]bool{}
    for i,f:=range packet.Facts{
        if f.Ref!=fmt.Sprintf("ev%d",i+1) || seen[f.Ref] || f.LinkConfidence<0 || f.LinkConfidence>100 {
            return errors.New("unsafe AI evidence reference")
        }
        seen[f.Ref]=true
        switch f.Source {
        case "suricata","wazuh","generic","ocsf":
        default:return errors.New("unsupported AI evidence source")
        }
        switch f.Kind{
        case "network","authentication","endpoint","other":
        default:return errors.New("unsupported AI event category")
        }
        switch f.Relation{
        case "alert_anchor","same_source_and_endpoints","same_source_and_host_ip",
            "independent_collector_endpoints","independent_collector_host_ip":
        default:return errors.New("unsupported AI linkage")
        }
    }
    return nil
}
func validateAIText(raw string,lo,hi int)error {
    if len(raw)<lo || len(raw)>hi || !utf8.ValidString(raw) ||
        strings.TrimSpace(raw)!=raw {return errors.New("invalid AI text length or spacing")}
    for _,r:=range raw {if unicode.IsControl(r){return errors.New("control characters in AI output")}}
    // Render as plain text in React; also disallow links, markup and code fences
    // so a model cannot convert the advisory panel into a phishing surface.
    lower:=strings.ToLower(raw)
    if strings.ContainsAny(raw,"<>") || strings.Contains(raw,"```") ||
        strings.Contains(lower,"http://") || strings.Contains(lower,"https://") {
        return errors.New("unsafe markup or URL in AI output")
    }
    return nil
}
// ParseAIAdvice rejects unknown fields, duplicate JSON fields, unsupported
// model artifacts, invalid evidence references, and unsupported verdict/action
// fields. A successful parse is STILL NOT evidence verification.
// rejectDuplicateAIKeys catches conflicting repeated JSON keys even inside
// nested model findings. DisallowUnknownFields alone does not reject repeats.
func rejectDuplicateAIKeys(raw []byte)error{
    dec:=json.NewDecoder(bytes.NewReader(raw))
    var walk func()error
    walk=func()error{
        tok,err:=dec.Token()
        if err!=nil{return err}
        delim,ok:=tok.(json.Delim)
        if !ok{return nil}
        switch delim{
        case '{':
            seen:=map[string]bool{}
            for dec.More(){
                keyToken,err:=dec.Token()
                if err!=nil{return err}
                key,ok:=keyToken.(string)
                if !ok{return errors.New("invalid JSON key")}
                if seen[key]{return errors.New("duplicate AI advisory JSON key")}
                seen[key]=true
                if err=walk();err!=nil{return err}
            }
            _,err=dec.Token()
            return err
        case '[':
            for dec.More(){
                if err=walk();err!=nil{return err}
            }
            _,err=dec.Token()
            return err
        default:return errors.New("invalid JSON delimiter")
        }
    }
    return walk()
}
func ParseAIAdvice(raw string, refs map[string]int64) (AIAdvice,error) {
    var out AIAdvice
    if len(raw)<2 || len(raw)>MaxAIAdviceBytes || !utf8.ValidString(raw){
        return out,errors.New("AI response size out of bounds")
    }
    if err:=rejectDuplicateAIKeys([]byte(raw));err!=nil{return AIAdvice{},err}
    dec:=json.NewDecoder(bytes.NewReader([]byte(raw)))
    dec.DisallowUnknownFields()
    if err:=dec.Decode(&out);err!=nil{return AIAdvice{},errors.New("invalid AI advisory JSON")}
    var extra any
    if err:=dec.Decode(&extra);err!=io.EOF {
        return AIAdvice{},errors.New("multiple AI advisory documents")
    }
    if err:=validateAIText(out.Summary,18,500);err!=nil{return AIAdvice{},err}
    if len(out.Findings)<1 || len(out.Findings)>3 {return AIAdvice{},errors.New("AI findings must have 1..3 entries")}
    seen:=map[string]bool{}
    for _,f:=range out.Findings{
        if refs[f.EvidenceRef]<=0 {return AIAdvice{},errors.New("fabricated AI evidence citation")}
        switch f.Category{
        case "verification_gap","corroboration","alternative_explanation":
        default: return AIAdvice{},errors.New("unsupported AI finding category")
        }
        if err:=validateAIText(f.Explanation,18,400);err!=nil{return AIAdvice{},err}
        key:=f.EvidenceRef+":"+f.Category
        if seen[key]{return AIAdvice{},errors.New("duplicate AI finding")}
        seen[key]=true
    }
    return out,nil
}

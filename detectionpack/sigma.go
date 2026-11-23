package detectionpack

// Sigma-compatible *subset* for immutable, reviewed normalized ARTEX telemetry.
// No generic Sigma queries, regex, filters, aggregation, arbitrary YAML uploads
// or back-end command generation. Unsupported semantics must be rejected.
import (
    "bytes"
    "embed"
    "errors"
    "fmt"
    "io"
    "regexp"
    "strings"
    "sync"

    "gopkg.in/yaml.v3"
)

//go:embed sigma/artex-normalized.yml
var sigmaAssets embed.FS

const sigmaRulesPath = "sigma/artex-normalized.yml"
const maxSigmaSize = 32 << 10
const maxSigmaRules = 12
const maxSigmaSelections = 6

var sigmaRuleID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// Exact technique and tactic pairs verified against ATT&CK Enterprise on
// 2026-11-23. This is a manually reviewed allowlist, not format-only validation.
// ATT&CK labels are unverified investigative hints, never event confirmation.
var reviewedATTACK = map[string]string{
    "T1685": "TA0112",   // Disable or Modify Tools / Defense Impairment (ATT&CK 2026)
    "T1059.001": "TA0002", // PowerShell / Execution
    "T1071.004": "TA0011", // DNS / Command and Control
    "T1003": "TA0006",   // OS Credential Dumping / Credential Access
}

type sigmaLogSource struct {
    Category string `yaml:"category"`
    Product string `yaml:"product"`
}
type sigmaExtension struct {
    Disposition string `yaml:"disposition"`
    FalsePositiveRisk string `yaml:"false_positive_risk"`
    Limitations string `yaml:"limitations"`
    AutoContainmentEligible bool `yaml:"auto_containment_eligible"`
}
type sigmaDetection struct {
    Selection map[string]any `yaml:"selection"`
    Condition string `yaml:"condition"`
}
type sigmaDocument struct {
    Title string `yaml:"title"`
    ID string `yaml:"id"`
    Status string `yaml:"status"`
    Description string `yaml:"description"`
    LogSource sigmaLogSource `yaml:"logsource"`
    Detection sigmaDetection `yaml:"detection"`
    Level string `yaml:"level"`
    FalsePositives []string `yaml:"falsepositives"`
    Tags []string `yaml:"tags"`
    Extension sigmaExtension `yaml:"x_artex"`
}
type compiledField struct {
    Key string
    Op string
    Values []string
}
type compiledSigma struct {
    Info SigmaRule
    Selection []compiledField
}
// SigmaRule is safe, bounded read-only metadata suitable for an admin catalog.
type SigmaRule struct {
    ID string `json:"id"`
    Title string `json:"title"`
    Severity string `json:"severity"`
    Technique string `json:"attack_technique"`
    Tactic string `json:"attack_tactic"`
    Condition string `json:"condition"`
    FalsePositiveRisk string `json:"false_positive_risk"`
    Limitations string `json:"limitations"`
    AutoContainmentEligible bool `json:"auto_containment_eligible"`
}
var supportedSigmaFields = map[string]bool{
    "source":true,"kind":true,"outcome":true,"action":true,
    "signature":true,"host":true,"username":true,
    "src_ip":true,"dst_ip":true,
}

func rejectYAMLFeatures(node *yaml.Node) error {
    if node.Kind == yaml.AliasNode || node.Anchor != "" || node.Tag == "!!binary" {
        return errors.New("YAML aliases, anchors and binary content are unsupported")
    }
    for _, child := range node.Content {
        if err:=rejectYAMLFeatures(child);err!=nil {return err}
    }
    return nil
}
func compileSelection(in map[string]any) ([]compiledField,error) {
    if len(in)==0 || len(in)>maxSigmaSelections {return nil,errors.New("selection must have 1..6 normalized fields")}
    out:=make([]compiledField,0,len(in))
    for raw,v:=range in {
        parts:=strings.Split(raw,"|")
        if len(parts)>2 || len(parts[0])==0 || !supportedSigmaFields[parts[0]] {
            return nil,fmt.Errorf("unsupported Sigma field %q",raw)
        }
        op:="equals"
        if len(parts)==2 {
            switch parts[1] {
            case "contains","startswith","endswith":
                op=parts[1]
            default:
                return nil,fmt.Errorf("unsupported Sigma modifier %q",raw)
            }
        }
        var values []string
        switch val:=v.(type) {
        case string:
            values=[]string{val}
        case []any:
            for _,item:=range val {
                s,ok:=item.(string)
                if !ok {return nil,fmt.Errorf("unsupported Sigma list item on %s",raw)}
                values=append(values,s)
            }
        default:
            return nil,fmt.Errorf("unsupported Sigma selection type on %s",raw)
        }
        if len(values)==0 || len(values)>12 {return nil,errors.New("Sigma selection must have 1..12 values")}
        for _,value:=range values {
            if value=="" || len(value)>128 || strings.TrimSpace(value)!=value || strings.ContainsAny(value,"\r\n\x00") {
                return nil,errors.New("invalid Sigma selection literal")
            }
            if strings.ContainsAny(value,"*?") {
                return nil,errors.New("Sigma wildcard matching is not implemented")
            }
        }
        out=append(out,compiledField{Key:parts[0],Op:op,Values:values})
    }
    // Map iteration order is irrelevant: fields are ANDed and lists are ORed.
    return out,nil
}
func compileSigma(raw []byte) ([]compiledSigma,error) {
    if len(raw)==0 || len(raw)>maxSigmaSize {return nil,errors.New("Sigma pack exceeds size limit")}
    dec:=yaml.NewDecoder(bytes.NewReader(raw))
    dec.KnownFields(true)
    seen:=map[string]bool{}
    var out []compiledSigma
    for {
        var node yaml.Node
        err:=dec.Decode(&node)
        if errors.Is(err,io.EOF) {break}
        if err!=nil{return nil,fmt.Errorf("malformed Sigma YAML: %w",err)}
        if len(node.Content)==0 {return nil,errors.New("empty Sigma YAML document")}
        if err:=rejectYAMLFeatures(&node);err!=nil{return nil,err}
        var d sigmaDocument
        if err:=node.Decode(&d);err!=nil{return nil,fmt.Errorf("unsupported Sigma schema: %w",err)}
        if len(out)>=maxSigmaRules {return nil,errors.New("too many Sigma rules")}
        if !sigmaRuleID.MatchString(d.ID) || seen[d.ID] {return nil,fmt.Errorf("invalid or duplicate Sigma ID %q",d.ID)}
        seen[d.ID]=true
        if d.Title=="" || len(d.Title)>120 || strings.ContainsAny(d.Title,"\r\n\x00") ||
            d.Description=="" || len(d.Description)>800 || d.Status!="experimental" ||
            d.LogSource.Category!="artex_normalized" || d.LogSource.Product!="artex-defense" {
            return nil,fmt.Errorf("invalid or unsupported normalized Sigma metadata %s",d.ID)
        }
        if d.Detection.Condition!="selection" {
            return nil,fmt.Errorf("unsupported Sigma condition %q",d.Detection.Condition)
        }
        selection,err:=compileSelection(d.Detection.Selection)
        if err!=nil{return nil,fmt.Errorf("rule %s: %w",d.ID,err)}
        if d.Level!="low" && d.Level!="medium" {
            return nil,fmt.Errorf("unsafe or unsupported Sigma severity for %s",d.ID)
        }
        if len(d.FalsePositives)==0 || len(d.FalsePositives)>10 ||
            d.Extension.Disposition!="alert_only" ||
            d.Extension.AutoContainmentEligible ||
            d.Extension.Limitations=="" ||
            (d.Extension.FalsePositiveRisk!="medium" && d.Extension.FalsePositiveRisk!="high") {
            return nil,fmt.Errorf("incomplete safety review for %s",d.ID)
        }
        // An exact reviewed technique/tactic pair is required. Reject invented
        // IDs, obsolete ATT&CK ids and arbitrary unreviewed tag combinations.
        if len(d.Tags)!=2 || !strings.HasPrefix(d.Tags[0],"attack.t") || !strings.HasPrefix(d.Tags[1],"attack.ta") {
            return nil,fmt.Errorf("missing ATT&CK reference pair for %s",d.ID)
        }
        technique:="T"+strings.TrimPrefix(d.Tags[0],"attack.t")
        tactic:="TA"+strings.TrimPrefix(d.Tags[1],"attack.ta")
        if reviewedATTACK[technique]!=tactic {return nil,fmt.Errorf("unreviewed ATT&CK reference %s / %s",technique,tactic)}
        out=append(out,compiledSigma{
            Info:SigmaRule{
                ID:d.ID,Title:d.Title,Severity:d.Level,Technique:technique,Tactic:tactic,
                Condition:d.Detection.Condition,FalsePositiveRisk:d.Extension.FalsePositiveRisk,
                Limitations:d.Extension.Limitations,AutoContainmentEligible:false,
            },
            Selection:selection,
        })
    }
    if len(out)==0 {return nil,errors.New("empty Sigma rule pack")}
    return out,nil
}
var sigmaCache struct {
    sync.Once
    Rules []compiledSigma
    Err error
}
func sigmaCompiled() ([]compiledSigma,error) {
    sigmaCache.Do(func(){
        raw,err:=sigmaAssets.ReadFile(sigmaRulesPath)
        if err!=nil {sigmaCache.Err=err;return}
        sigmaCache.Rules,sigmaCache.Err=compileSigma(raw)
    })
    return sigmaCache.Rules,sigmaCache.Err
}
func SigmaCatalog() ([]SigmaRule,error) {
    rules,err:=sigmaCompiled()
    if err!=nil{return nil,err}
    out:=make([]SigmaRule,0,len(rules))
    for _,rule:=range rules {out=append(out,rule.Info)}
    return out,nil
}
func SigmaArtifact() ([]byte,error) {
    if _,err:=sigmaCompiled();err!=nil{return nil,err}
    return sigmaAssets.ReadFile(sigmaRulesPath)
}
func sigmaEquals(op,value,needle string) bool {
    switch op {
    case "equals":return strings.EqualFold(value,needle)
    case "contains":return strings.Contains(strings.ToLower(value),strings.ToLower(needle))
    case "startswith":return strings.HasPrefix(strings.ToLower(value),strings.ToLower(needle))
    case "endswith":return strings.HasSuffix(strings.ToLower(value),strings.ToLower(needle))
    }
    return false
}
// SigmaMatch reads a *normalized* event projection only. It never evaluates
// arbitrary templates, regexes, command strings or raw vendor JSON.
func SigmaMatch(fields map[string]string) ([]SigmaRule,error) {
    rules,err:=sigmaCompiled()
    if err!=nil{return nil,err}
    var out []SigmaRule
    for _,r:=range rules {
        matched:=true
        for _,term:=range r.Selection {
            field:=fields[term.Key]
            if field=="" {matched=false;break}
            yes:=false
            for _,v:=range term.Values {if sigmaEquals(term.Op,field,v){yes=true;break}}
            if !yes {matched=false;break}
        }
        if matched {out=append(out,r.Info)}
    }
    return out,nil
}
func SigmaATTACKHint(ruleID string) (string,string,bool) {
    if !strings.HasPrefix(ruleID,"sigma_") {return "","",false}
    id:=strings.TrimPrefix(ruleID,"sigma_")
    rules,err:=sigmaCompiled()
    if err!=nil{return "","",false}
    for _,r:=range rules {
        if r.Info.ID==id {return r.Info.Technique,r.Info.Tactic,true}
    }
    return "","",false
}
func ValidateSigma() error {
    _,err:=sigmaCompiled()
    return err
}

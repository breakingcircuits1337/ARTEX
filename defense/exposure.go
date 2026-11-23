package defense

import (
 "net/url"
 "sort"
 "strings"

 "github.com/Autumn-27/artex/db"
)

// Exposure is an evidence-limited review candidate, NOT a confirmed vulnerability.
type Exposure struct {
 AssetID int64 `json:"asset_id"`
 AssetType string `json:"asset_type"`
 Level string `json:"level"`
 Signals []string `json:"signals"`
 RecommendedChecks []string `json:"recommended_checks"`
 Confidence string `json:"confidence"`
}

// AssessAsset evaluates only already-recorded asset metadata. It performs no
// network requests and never asserts that a service is externally reachable.
func AssessAsset(a *db.Asset) Exposure {
 out := Exposure{AssetID:a.ID, AssetType:a.Type, Level:"informational", Confidence:"metadata-only"}
 if a.Port != nil {
  ports := map[int]string{
   22:"SSH administration", 3389:"RDP administration",
   5900:"VNC remote desktop", 2375:"unencrypted Docker API",
   6443:"Kubernetes API", 9200:"Elasticsearch API",
   27017:"MongoDB", 5432:"PostgreSQL", 6379:"Redis",
  }
  if label, ok := ports[*a.Port]; ok {
   out.Level = "review"
   out.Signals = append(out.Signals, "recorded service port "+label)
   out.RecommendedChecks = append(out.RecommendedChecks, "Confirm ownership, reachability, intended exposure and network access controls from approved inventory.")
  }
 }
 if a.URL != "" {
  if u, err := url.Parse(a.URL); err == nil && strings.EqualFold(u.Scheme,"http") {
   out.Level = "review"
   out.Signals = append(out.Signals, "recorded endpoint uses HTTP rather than HTTPS")
   out.RecommendedChecks = append(out.RecommendedChecks, "Confirm whether TLS termination or a trusted encrypted transport is provided upstream.")
  }
 }
 if len(out.Signals) == 0 {
  out.Signals = []string{"No predefined exposure indicators found in the available asset metadata."}
  out.RecommendedChecks = []string{"Correlate with owner-approved configuration, vulnerability findings and network visibility before drawing a security conclusion."}
 }
 return out
}

// AssessAssets returns stable ordering with actionable review candidates first.
func AssessAssets(assets []*db.Asset) []Exposure {
 results := make([]Exposure,0,len(assets))
 for _, a := range assets { if a != nil { results=append(results, AssessAsset(a)) } }
 sort.SliceStable(results,func(i,j int)bool{
  if results[i].Level != results[j].Level { return results[i].Level == "review" }
  return results[i].AssetID < results[j].AssetID
 })
 return results
}

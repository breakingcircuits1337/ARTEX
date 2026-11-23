package defense

import (
	"strings"
	"testing"
)

func TestAnalyzeInvestigationConservativeSingleAlert(t *testing.T) {
	s := InvestigationSnapshot{
		AnchorEventID: 42, RuleID: "curated_suricata_9900001", AlertSeverity: "critical",
		Observations: []InvestigationObservation{{EventID: 42, Source: "suricata", LinkReason: "alert_anchor", LinkConfidence: 95}},
	}
	findings := AnalyzeInvestigation(s)
	if len(findings) != 2 {
		t.Fatalf("single unverified alert should yield context and coverage gap, got %+v", findings)
	}
	if findings[0].Category != "alert_context" || findings[0].Confidence > 30 ||
		findings[0].EvidenceEventID != 42 {
		t.Fatalf("initial signal overstated or lost provenance: %+v", findings[0])
	}
	if findings[1].Category != "coverage_gap" || findings[1].Confidence != 0 ||
		!strings.Contains(findings[1].Explanation, "independent sensor") {
		t.Fatalf("failed to record uncertainty: %+v", findings[1])
	}
	for _, finding := range findings {
		if strings.Contains(strings.ToLower(finding.Explanation), "confirmed compromise") {
			t.Fatalf("unexpected certainty: %+v", finding)
		}
	}
}

func TestAnalyzeInvestigationCorroborationAndHintsRemainHypotheses(t *testing.T) {
	s := InvestigationSnapshot{
		AnchorEventID: 7, RuleID: "password_spray_v1",
		AssetIDs: []int64{3, 4},
		Observations: []InvestigationObservation{
			{EventID: 7, Source: "wazuh", LinkReason: "alert_anchor", LinkConfidence: 95},
			{EventID: 8, Source: "wazuh", LinkReason: "same_source_and_endpoints", LinkConfidence: 55},
			{EventID: 8, Source: "wazuh", LinkReason: "same_source_and_endpoints", LinkConfidence: 55},
		},
		Techniques: []InvestigationTechnique{{EventID: 7, Technique: "T1110.003", Confidence: 90, Origin: "analyst_hypothesis"}},
	}
	findings := AnalyzeInvestigation(s)
	if len(findings) != 5 {
		t.Fatalf("expected all five evidence review lenses, got %+v", findings)
	}
	seen := map[string]bool{}
	for _, f := range findings {
		if f.Confidence > 55 || f.EvidenceEventID <= 0 {
			t.Fatalf("investigator asserted unsourced/high-confidence claim: %+v", f)
		}
		seen[f.Category] = true
		if f.Category == "corroboration" && !strings.Contains(f.Explanation, "2 normalized") {
			t.Fatalf("deduplication failed: %+v", f)
		}
		if f.Category == "technique_hypothesis" && f.Confidence > 45 {
			t.Fatalf("technique confidence must be capped: %+v", f)
		}
	}
	for _, key := range []string{"alert_context", "corroboration", "asset_context", "technique_hypothesis", "coverage_gap"} {
		if !seen[key] {
			t.Fatalf("missing review lens %s", key)
		}
	}
}

func TestAnalyzeInvestigationNeverInventsEvidence(t *testing.T) {
	if f := AnalyzeInvestigation(InvestigationSnapshot{}); len(f) != 0 {
		t.Fatalf("missing source anchor produced findings: %+v", f)
	}
}

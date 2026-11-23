// Package defense contains deterministic, nonexecuting defensive analysis.
// These reviewable passes deliberately do not call agents, LLMs, networks,
// shell tools or response/containment adapters.
package defense

import (
	"fmt"
	"strings"
)

type InvestigationObservation struct {
	EventID          int64
	Source           string
	LinkReason       string
	LinkConfidence   int
}
type InvestigationTechnique struct {
	EventID    int64
	Technique  string
	Confidence int
	Origin     string
}
type InvestigationSnapshot struct {
	AnchorEventID int64
	RuleID        string
	AlertSeverity string
	AssetIDs      []int64
	Observations  []InvestigationObservation
	Techniques    []InvestigationTechnique
}
type InvestigationFinding struct {
	Category        string
	Title           string
	Explanation     string
	Confidence      int
	EvidenceEventID int64
}

// AnalyzeInvestigation implements four independent evidence-review lenses:
// signal context, corroboration, inventory linkage, and missing evidence.
// Confidence describes *support for a review hypothesis*, not compromise.
// Nothing in this package grants emergency/response authorization.
func AnalyzeInvestigation(s InvestigationSnapshot) []InvestigationFinding {
	if s.AnchorEventID <= 0 {
		return nil
	}
	findings := []InvestigationFinding{{
		Category: "alert_context",
		Title: "Unverified sensor alert",
		Explanation: "A stored security alert triggered this case. Its source record requires independent operator verification; signature strings and vendor severity are not proof of malicious activity.",
		Confidence: 30,
		EvidenceEventID: s.AnchorEventID,
	}}
	distinct := map[int64]struct{}{}
	var strongest int
	for _, e := range s.Observations {
		if e.EventID > 0 {
			distinct[e.EventID] = struct{}{}
			if e.EventID != s.AnchorEventID && e.LinkConfidence > strongest {
				strongest = e.LinkConfidence
			}
		}
	}
	if len(distinct) > 1 {
		// Phase 6 requires same sensor source plus two matching endpoint
		// fields. These are related records, not independent verification.
		findings = append(findings, InvestigationFinding{
			Category: "corroboration",
			Title: "Repeated same-source observations",
			Explanation: fmt.Sprintf("%d normalized events were linked by Phase 6 source-and-endpoint matching. They may share one sensor or network path and do not independently confirm exploitation. Review original event IDs.", len(distinct)),
			Confidence: min(strongest, 55),
			EvidenceEventID: s.AnchorEventID,
		})
	}
	if len(s.AssetIDs) > 0 {
		findings = append(findings, InvestigationFinding{
			Category: "asset_context",
			Title: "Inventory associations require owner review",
			Explanation: fmt.Sprintf("%d stored asset identifiers were attached to the source alert. Inventory matches are not evidence of exposure, reachability or successful compromise; verify ownership and safety constraints.", len(s.AssetIDs)),
			Confidence: 30,
			EvidenceEventID: s.AnchorEventID,
		})
	}
	if len(s.Techniques) > 0 {
		var hint string
		var evidenceID int64
		maxConfidence := 0
		for _, m := range s.Techniques {
			if m.EventID <= 0 || m.Technique == "" {
				continue
			}
			if hint == "" {
				hint = m.Technique
				evidenceID = m.EventID
			}
			if m.Confidence > maxConfidence {
				maxConfidence = m.Confidence
			}
		}
		if hint != "" {
			findings = append(findings, InvestigationFinding{
				Category: "technique_hypothesis",
				Title: "ATT&CK hypothesis requires corroboration",
				Explanation: fmt.Sprintf("A stored, unconfirmed ATT&CK mapping (including %s) may guide follow-up. Validate the behavior against primary sensor evidence; the mapping does not establish technique execution or threat-actor identity.", hint),
				Confidence: min(maxConfidence, 45),
				EvidenceEventID: evidenceID,
			})
		}
	}
	var needs []string
	if len(distinct) < 2 {
		needs = append(needs, "only one correlated event is recorded")
	}
	if len(s.AssetIDs) == 0 {
		needs = append(needs, "no existing inventory assets are linked")
	}
	// Phase 6 only links events from the same sensor vendor. Missing
	// independent sensor validation is always explicitly documented.
	needs = append(needs, "independent sensor corroboration is not established")
	findings = append(findings, InvestigationFinding{
		Category: "coverage_gap",
		Title: "Evidence gaps and alternative explanations",
		Explanation: "Analyst follow-up recommended: " + strings.Join(needs, "; ") + ". Check benign administration, authorized testing, sensor spoofing and missing logs before concluding.",
		Confidence: 0,
		EvidenceEventID: s.AnchorEventID,
	})
	return findings
}

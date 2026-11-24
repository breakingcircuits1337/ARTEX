package defense

import (
	"strings"
	"testing"
)

func TestAIPTYARAObservationCarriesDRLAuthorAndCannotContain(t *testing.T) {
	hits := EvaluateEvent(SecurityEvent{
		Source:    "generic",
		Kind:      "endpoint",
		Signature: "AIPT_ARTEX_Transcript_File",
	})
	if len(hits) != 1 {
		t.Fatalf("AIPT rule observation produced %d findings, want one", len(hits))
	}
	hit := hits[0]
	if hit.RuleID != "curated_yara_AIPT_ARTEX_Transcript_File" ||
		!strings.Contains(hit.Title, "unverified") ||
		!strings.Contains(hit.Summary, "Xint (DRL-1.1)") {
		t.Fatalf("wrong rule identity, safety label or license attribution: %+v", hit)
	}
	if hits := EvaluateEvent(SecurityEvent{Source: "generic", Kind: "endpoint",
		Signature: "ARTEX_Go_Module_Cache"}); len(hits) != 0 {
		t.Fatalf("quarantined legacy source YARA rule generated alerts: %+v", hits)
	}
	if hits := EvaluateEvent(SecurityEvent{Source: "generic", Kind: "endpoint",
		Signature: "AIPT_ARTEX_Transcript_File", VendorAlert: true}); len(hits) != 1 ||
		hits[0].RuleID != "curated_yara_AIPT_ARTEX_Transcript_File" {
		t.Fatalf("YARA match incorrectly followed privileged vendor alert path: %+v", hits)
	}
}

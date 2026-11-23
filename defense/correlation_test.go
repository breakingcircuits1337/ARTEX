package defense

import (
	"strings"
	"testing"
)

func TestCaseIndicatorsAreObservedAndBounded(t *testing.T) {
	got := CaseIndicators(" 2001:db8::1 ", "198.51.100.2", "Router.Example", "Sensor Sign")
	if len(got) != 4 {
		t.Fatalf("expected 4 direct observations, got %+v", got)
	}
	if got[0].Type != "ip" || got[0].Role != "source_ip" ||
		got[0].Value != "2001:db8::1" {
		t.Fatalf("wrong canonical source IP: %+v", got[0])
	}
	if got[1].Value != "198.51.100.2" || got[1].Role != "destination_ip" {
		t.Fatalf("wrong destination evidence: %+v", got[1])
	}
	if got[2].Value != "router.example" || got[2].Role != "host" {
		t.Fatalf("host normalization incorrect: %+v", got[2])
	}
	if got[3].Role != "sensor_signature" {
		t.Fatalf("signature provenance missing: %+v", got[3])
	}
}

func TestCaseIndicatorsRejectMalformedAndSensitiveFreeText(t *testing.T) {
	got := CaseIndicators("192.0.2.999", "198.51.100.2:443",
		"secret\nheader", strings.Repeat("x", 300))
	if len(got) != 0 {
		t.Fatalf("untrusted fields were incorrectly persisted as indicators: %+v", got)
	}
	if got := CaseIndicators("::ffff:192.0.2.8", "", "", ""); len(got) != 1 ||
		got[0].Value != "192.0.2.8" {
		t.Fatalf("mapped IPv4 canonicalization failed: %+v", got)
	}
}

func TestATTACKHypothesisRequiresScopedEvidenceConfidence(t *testing.T) {
	if _, err := ValidateATTACKHypothesis("T1110.003", "TA0006", 65,
		"Source evidence suggests password spraying; investigate alternatives."); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		technique, tactic string
		confidence        int
		reason            string
	}{
		{"T1110;DROP", "TA0006", 60, "Enough supporting analyst rationale"},
		{"T1110.3", "TA0006", 60, "Enough supporting analyst rationale"},
		{"T1110", "T0006", 60, "Enough supporting analyst rationale"},
		{"T1110", "", 0, "Enough supporting analyst rationale"},
		{"T1110", "", 100, "Enough supporting analyst rationale"},
		{"T1110", "", 30, "short"},
	} {
		if _, err := ValidateATTACKHypothesis(tc.technique, tc.tactic,
			tc.confidence, tc.reason); err == nil {
			t.Fatalf("accepted invalid mapping %+v", tc)
		}
	}
}

func TestOnlyReviewedBehavioralRulesReceiveATTACKHints(t *testing.T) {
	technique, tactic, ok := KnownRuleATTACKHint("password_spray_v1")
	if !ok || technique != "T1110.003" || tactic != "TA0006" {
		t.Fatalf("unexpected rule hint %s %s %v", technique, tactic, ok)
	}
	for _, rule := range []string{
		"curated_suricata_9900001", "curated_yara_ARTEX_JSP_Webshell_Numbered",
		"unknown", "suricata_critical",
	} {
		if _, _, ok := KnownRuleATTACKHint(rule); ok {
			t.Fatalf("unreviewed rule %q mapped automatically", rule)
		}
	}
}

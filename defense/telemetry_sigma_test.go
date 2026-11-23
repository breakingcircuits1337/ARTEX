package defense

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestSigmaDetectionFromNormalizedEvent(t *testing.T) {
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	samples := []struct {
		raw       string
		ruleID    string
		technique string
	}{
		{`{"event_id":"s1","kind":"endpoint","action":"security_agent_disabled"}`, "sigma_9ab1e612-46ba-40bd-91d5-31d4ee36f001", "T1685"},
		{`{"event_id":"s2","kind":"endpoint","action":"powershell_encoded_command"}`, "sigma_8f70ef12-a5e9-439d-a173-4d8546932002", "T1059.001"},
		{`{"event_id":"s3","kind":"network","action":"dns_tunnel_suspected"}`, "sigma_7c89f13b-7497-4cc7-ae91-d8ca910da003", "T1071.004"},
		{`{"event_id":"s4","kind":"endpoint","action":"credential_dump_reported"}`, "sigma_41a367b9-f14d-4d30-96de-d28601f78004", "T1003"},
	}
	for _, tc := range samples {
		e, err := NormalizeEvent("generic", json.RawMessage(tc.raw), now)
		if err != nil {
			t.Fatal(err)
		}
		hits, err := EvaluateEventWithSigma(e)
		if err != nil || len(hits) != 1 {
			t.Fatalf("%s hits=%+v err=%v", tc.raw, hits, err)
		}
		if hits[0].RuleID != tc.ruleID || hits[0].Severity != "medium" ||
			!strings.Contains(hits[0].Summary, "alert-only") ||
			e.VendorAlert {
			t.Fatalf("unsafe match %+v from %+v", hits, e)
		}
		technique, _, ok := KnownRuleATTACKHint(hits[0].RuleID)
		if !ok || technique != tc.technique {
			t.Fatalf("bad ATT&CK link %s", technique)
		}
	}
	if tech, tactic, ok := KnownRuleATTACKHint("auth_guess_burst_v1"); !ok || tech != "T1110.001" || tactic != "TA0006" {
		t.Fatalf("password guessing mapping %s/%s %v", tech, tactic, ok)
	}
	for _, rule := range []string{"curated_yara_ARTEX_JSP_Webshell_Numbered",
		"sigma_deadbeef-0000-4000-8000-000000000000",
		"vendor_alert_v1"} {
		if _, _, ok := KnownRuleATTACKHint(rule); ok {
			t.Fatalf("unreviewed ATT&CK hint for %s", rule)
		}
	}
}

func TestSigmaDoesNotUpgradeVendorAlertOrAuthorizeAction(t *testing.T) {
	e := SecurityEvent{Source: "generic", Kind: "endpoint", Action: "security_agent_disabled",
		VendorAlert: false, Severity: 0}
	hits, err := EvaluateEventWithSigma(e)
	if err != nil || len(hits) != 1 || e.VendorAlert || e.Severity != 0 {
		t.Fatalf("Sigma mutated event trust: %+v hits=%+v err=%v", e, hits, err)
	}
	// An unrelated upstream alert still may exist. This new Sigma labeling
	// cannot synthesize or upgrade the vendor's assertion.
	e.VendorAlert = true
	e.Signature = "upstream report"
	hits, err = EvaluateEventWithSigma(e)
	if err != nil || len(hits) != 2 {
		t.Fatalf("upstream alert lost on Sigma match: hits=%+v err=%v", hits, err)
	}
}

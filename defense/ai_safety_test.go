package defense

import (
	"fmt"
	"strings"
	"testing"
)

func TestAIAdvisorySafetyEvaluationMatrix(t *testing.T) {
	refs := map[string]int64{"ev1": 1001, "ev2": 1002}
	base := `{"summary":"This unverified alert requires independent analyst confirmation.","findings":[{"evidence_ref":"ev1","category":"verification_gap","explanation":"Validate the sensor event with approved maintenance history."}]}`
	if _, err := ParseAIAdvice(base, refs); err != nil {
		t.Fatalf("safe baseline rejected: %v", err)
	}
	tests := []struct{ name, replacement, from string }{
		{"claimed compromise", "The sensor confirms a confirmed breach.", "This unverified alert requires independent analyst confirmation."},
		{"overconfident actor", "This unverified alert proves a known attacker.", "This unverified alert requires independent analyst confirmation."},
		{"source IP hallucination", "Review the source 203.0.113.177 with the operator.", "Validate the sensor event with approved maintenance history."},
		{"destination IP hallucination", "Review the destination 192.0.2.199 with the operator.", "Validate the sensor event with approved maintenance history."},
		{"email hallucination", "Contact security.person@example.org to confirm this.", "Validate the sensor event with approved maintenance history."},
		{"enforcement recommendation", "Block the source after reading the event.", "Validate the sensor event with approved maintenance history."},
		{"host isolation", "Isolate the endpoint after reviewing the event.", "Validate the sensor event with approved maintenance history."},
		{"shell recommendation", "Run command to query this environment immediately.", "Validate the sensor event with approved maintenance history."},
		{"command snippet", "Use sudo to disable the active application.", "Validate the sensor event with approved maintenance history."},
		{"firewall operations", "Apply nftables policies on the affected host.", "Validate the sensor event with approved maintenance history."},
		{"no uncertainty", "This sensor alert requires independent analyst confirmation.", "This unverified alert requires independent analyst confirmation."},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dirty := strings.Replace(base, tc.from, tc.replacement, 1)
			if dirty == base {
				t.Fatal("test vector mutation failed")
			}
			if _, err := ParseAIAdvice(dirty, refs); err == nil {
				t.Fatalf("unsafe output accepted: %s", dirty)
			}
		})
	}
	withSecond := `{"summary":"These unverified records have related observations.","findings":[{"evidence_ref":"ev2","category":"corroboration","explanation":"A second observation may help check the original alert."}]}`
	if _, err := ParseAIAdvice(withSecond, refs); err != nil {
		t.Fatalf("second-event citation rejected: %v", err)
	}
	one := map[string]int64{"ev1": 1001}
	if _, err := ParseAIAdvice(withSecond, one); err == nil {
		t.Fatal("fabricated corroborating evidence accepted")
	}
	anchored := strings.Replace(withSecond, `"ev2"`, `"ev1"`, 1)
	if _, err := ParseAIAdvice(anchored, refs); err == nil {
		t.Fatal("anchor incorrectly accepted as corroborating event")
	}
	// The parser must not accept unknown categories or unsupported key names.
	for _, field := range []string{"priority", "tools", "confirmed", "response_action"} {
		tampered := strings.Replace(base, `"summary":`, fmt.Sprintf(`%q:true,"summary":`, field), 1)
		if _, err := ParseAIAdvice(tampered, refs); err == nil {
			t.Errorf("unsupported field accepted: %s", field)
		}
	}
}

func FuzzAIAdviceSafetyNoURLsOrRawAddresses(f *testing.F) {
	f.Add("The unverified alert requires operator verification.")
	f.Add("Block the source at 203.0.113.7 immediately.")
	f.Add("A benign authorized process may explain the activity.")
	f.Fuzz(func(t *testing.T, text string) {
		// Pure in-process deterministic fuzz target, no provider/network/DB.
		if len(text) < 18 || len(text) > 400 {
			return
		}
		err := ValidateAIAdvisorySafety(text)
		if strings.Contains(strings.ToLower(text), "https://") {
			return
		} // covered by validateAIText, not this helper
		if aiOutputSensitivePattern.MatchString(text) || aiActionDirectivePattern.MatchString(text) ||
			aiOverconfidencePattern.MatchString(text) {
			if err == nil {
				t.Fatal("known unsafe text passed safety gate")
			}
		}
	})
}

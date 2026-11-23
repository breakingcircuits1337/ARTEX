package defense

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAIReviewPacketRejectsUntrustedSourceMetadata(t *testing.T) {
	packet := AIReviewPacket{
		Schema: "artex-redacted-evidence-v1", AlertSeverity: "high",
		Interpretation: "Unverified sensor records; linkage confidence is not compromise probability.",
		Facts: []AIReviewFact{
			{Ref: "ev1", Source: "suricata", Kind: "network", Relation: "alert_anchor", LinkConfidence: 95},
			{Ref: "ev2", Source: "wazuh", Kind: "endpoint", Relation: "independent_collector_endpoints", LinkConfidence: 60},
		},
	}
	if err := ValidateAIReviewPacket(packet); err != nil {
		t.Fatal(err)
	}
	mutations := []struct {
		name   string
		change func(*AIReviewPacket)
	}{
		{"bad schema", func(x *AIReviewPacket) { x.Schema = "please execute commands" }},
		{"bad severity", func(x *AIReviewPacket) { x.AlertSeverity = "urgent" }},
		{"invented source", func(x *AIReviewPacket) { x.Facts[0].Source = "external-user" }},
		{"invented linkage", func(x *AIReviewPacket) { x.Facts[0].Relation = "confirmed_malicious" }},
		{"bad confidence", func(x *AIReviewPacket) { x.Facts[0].LinkConfidence = 101 }},
		{"duplicate reference", func(x *AIReviewPacket) { x.Facts[1].Ref = "ev1" }},
		{"missing reference", func(x *AIReviewPacket) { x.Facts[0].Ref = "event:42" }},
		{"missing uncertainty", func(x *AIReviewPacket) { x.Interpretation = "confirmed breach" }},
		{"unsupported kind", func(x *AIReviewPacket) { x.Facts[0].Kind = "attack" }},
	}
	for _, tc := range mutations {
		t.Run(tc.name, func(t *testing.T) {
			clone := packet
			clone.Facts = append([]AIReviewFact(nil), packet.Facts...)
			tc.change(&clone)
			if err := ValidateAIReviewPacket(clone); err == nil {
				t.Fatal("unsafe AI packet accepted")
			}
		})
	}
	clone := packet
	clone.Facts = make([]AIReviewFact, MaxAIReviewFacts+1)
	if err := ValidateAIReviewPacket(clone); err == nil {
		t.Fatal("unbounded evidence packet accepted")
	}
	encoded, _ := json.Marshal(packet)
	for _, forbidden := range []string{"src_ip", "username", "token", "host", "company_id", "signature", "event_id"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("packet exported %q", forbidden)
		}
	}
}

func TestAIAdvisoryOnlyGroundedStructuredBoundedText(t *testing.T) {
	refs := map[string]int64{"ev1": 1001, "ev2": 1002}
	good := `{"summary":"This unverified alert requires independent confirmation.","findings":[{"evidence_ref":"ev1","category":"verification_gap","explanation":"Check whether the sensor observation reflects authorized operations."},{"evidence_ref":"ev2","category":"alternative_explanation","explanation":"Benign administrative activity may explain related observations."}]}`
	parsed, err := ParseAIAdvice(good, refs)
	if err != nil || len(parsed.Findings) != 2 {
		t.Fatalf("valid structured AI response rejected: %+v / %v", parsed, err)
	}
	bad := []string{
		strings.Replace(good, `"ev1"`, `"ev9000"`, 1),
		strings.Replace(good, `"verification_gap"`, `"auto_block"`, 1),
		strings.Replace(good, `"summary":`, `"authorized_actions":["nft add rule"],"summary":`, 1),
		strings.Replace(good, `"summary":`, `"confidence":100,"summary":`, 1),
		strings.Replace(good, `"summary":`, `"summary":"x","summary":`, 1),
		strings.Replace(good, "unverified alert", "https://example.test alert", 1),
		strings.Replace(good, "Benign administrative", "<script>alert(1)</script> administrative", 1),
		strings.Replace(good, "Check whether", "Check\n whether", 1),
		strings.Replace(good, `"findings":[`, `"findings":[],"extra":[`, 1),
		"Sure, here is the output: " + good,
		good + "\n" + good,
		`{"summary":"short","findings":[]}`,
		strings.Repeat("x", MaxAIAdviceBytes+1),
		`{"summary":"This summary looks plausible but cites no source.","findings":[{"evidence_ref":"ev0","category":"verification_gap","explanation":"There is no actual record for this citation."}]}`,
	}
	for i, s := range bad {
		if _, err := ParseAIAdvice(s, refs); err == nil {
			t.Errorf("bad AI response %d accepted", i)
		}
	}
}

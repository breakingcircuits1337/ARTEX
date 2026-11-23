package detectionpack

import (
	"strings"
	"testing"
)

func TestSigmaReviewedRuleCatalogAndArtifact(t *testing.T) {
	if err := ValidateSigma(); err != nil {
		t.Fatal(err)
	}
	if err := Validate(); err != nil {
		t.Fatalf("full detection pack invalid: %v", err)
	}
	catalog, err := SigmaCatalog()
	if err != nil {
		t.Fatal(err)
	}
	if len(catalog) != 4 {
		t.Fatalf("reviewed rule count=%d", len(catalog))
	}
	seen := map[string]bool{}
	for _, rule := range catalog {
		if rule.ID == "" || rule.Title == "" || rule.Severity != "medium" ||
			rule.Technique == "" || rule.Tactic == "" ||
			rule.Limitations == "" || rule.AutoContainmentEligible || seen[rule.ID] {
			t.Fatalf("unsafe or duplicate reviewed Sigma metadata: %+v", rule)
		}
		seen[rule.ID] = true
		if reviewedATTACK[rule.Technique] != rule.Tactic {
			t.Fatalf("unreviewed ATT&CK pair: %+v", rule)
		}
		tech, tactic, ok := SigmaATTACKHint("sigma_" + rule.ID)
		if !ok || tech != rule.Technique || tactic != rule.Tactic {
			t.Fatalf("ATT&CK mapping lost %q", rule.ID)
		}
	}
	raw, err := Rules("sigma")
	if err != nil || !strings.Contains(string(raw), "artex_normalized") {
		t.Fatalf("fixed Sigma artifact missing: %v", err)
	}
	if _, err := Rules("../sigma/artex-normalized.yml"); err == nil {
		t.Fatal("path traversal rule file accepted")
	}
}

func TestSigmaNormalizedFieldFixtures(t *testing.T) {
	cases := []struct {
		name      string
		fields    map[string]string
		technique string
	}{
		{"tamper", map[string]string{"kind": "endpoint", "action": "security_agent_disabled"}, "T1685"},
		{"tamper-alt", map[string]string{"kind": "endpoint", "action": "edr_service_stopped"}, "T1685"},
		{"powershell", map[string]string{"kind": "endpoint", "action": "powershell_encoded_command"}, "T1059.001"},
		{"dns", map[string]string{"kind": "network", "action": "dns_tunnel_suspected"}, "T1071.004"},
		{"credential", map[string]string{"kind": "endpoint", "action": "credential_dump_reported"}, "T1003"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rules, err := SigmaMatch(tc.fields)
			if err != nil || len(rules) != 1 || rules[0].Technique != tc.technique {
				t.Fatalf("matched=%+v err=%v", rules, err)
			}
		})
	}
	negatives := []map[string]string{
		{"kind": "authentication", "action": "security_agent_disabled"},
		{"kind": "endpoint", "action": "security_agent_running"},
		{"kind": "network", "action": "normal_dns_query"},
		{"kind": "endpoint", "action": "powershell_enc"},
		{"kind": "endpoint", "signature": "security_agent_disabled"},
		{"kind": "endpoint", "action": "credential_dump_reported_extra"},
		{"action": "credential_dump_reported"},
	}
	for i, fields := range negatives {
		hits, err := SigmaMatch(fields)
		if err != nil || len(hits) > 0 {
			t.Fatalf("negative %d incorrectly matched %+v err=%v", i, hits, err)
		}
	}
}

func TestSigmaStrictSchemaRejectsUnsupportedAndDangerousSyntax(t *testing.T) {
	raw, err := SigmaArtifact()
	if err != nil {
		t.Fatal(err)
	}
	variants := []struct {
		name string
		src  string
	}{
		{"condition grammar", strings.Replace(string(raw), "condition: selection", "condition: selection or filter", 1)},
		{"unknown field", strings.Replace(string(raw), "  condition: selection", "  another: pass\n  condition: selection", 1)},
		{"unreviewed technique", strings.Replace(string(raw), "attack.t1685", "attack.t9999", 1)},
		{"obsolete mapping", strings.Replace(string(raw), "attack.t1685", "attack.t1562.001", 1)},
		{"wrong tactic", strings.Replace(string(raw), "attack.ta0112", "attack.ta0002", 1)},
		{"auto block", strings.Replace(string(raw), "auto_containment_eligible: false", "auto_containment_eligible: true", 1)},
		{"unsupported severity", strings.Replace(string(raw), "level: medium", "level: critical", 1)},
		{"selector regex", strings.Replace(string(raw), "    action:", "    action|re:", 1)},
		{"wildcard", strings.Replace(string(raw), "security_agent_disabled", "security_*", 1)},
		{"missing selection", strings.Replace(string(raw), "  selection:", "  badselection:", 1)},
		{"unknown top-level", strings.Replace(string(raw), "status: experimental", "status: experimental\nunsafe: yes", 1)},
		{"duplicate identifier", strings.Replace(string(raw),
			"8f70ef12-a5e9-439d-a173-4d8546932002",
			"9ab1e612-46ba-40bd-91d5-31d4ee36f001", 1)},
		{"alias", strings.Replace(string(raw), "kind: endpoint", "kind: &mykind endpoint", 1)},
	}
	for _, tc := range variants {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := compileSigma([]byte(tc.src)); err == nil {
				t.Fatal("unsupported Sigma content compiled")
			}
		})
	}
	for _, raw := range [][]byte{nil, make([]byte, maxSigmaSize+1), []byte("title: incomplete\n")} {
		if _, err := compileSigma(raw); err == nil {
			t.Fatal("invalid/oversized Sigma pack compiled")
		}
	}
}

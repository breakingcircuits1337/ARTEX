package detectionpack

import (
	"bytes"
	"strings"
	"testing"
)

func TestCatalogOnlyContainsAlertRules(t *testing.T) {
	if err := Validate(); err != nil {
		t.Fatalf("invalid detection pack: %v", err)
	}
	catalog, err := Catalog()
	if err != nil { t.Fatal(err) }
	if catalog.Policy != "alert_only" || catalog.DefaultDeployed ||
		catalog.ExecutionEnabled || catalog.AutonomousContainmentEnabled {
		t.Fatal("catalog could enable active defensive actions")
	}
	if catalog.RuleCount != 10 || catalog.QuarantinedCount != 15 {
		t.Fatalf("unexpected curated/quarantined counts: %+v", catalog)
	}
	for _, rule := range catalog.Rules {
		if rule.AutoContainmentEligible || !rule.OperatorInstallRequired {
			t.Fatalf("rule %s could authorize containment", rule.ID)
		}
		if rule.FalsePositiveRisk == "" || rule.Limitations == "" {
			t.Fatalf("rule %s missing safety review", rule.ID)
		}
	}
}

func TestDownloadsAreFixedAlertOnlyAssets(t *testing.T) {
	for _, engine := range []string{"suricata", "yara"} {
		raw, err := Rules(engine)
		if err != nil || len(raw) < 128 {
			t.Fatalf("%s rules unavailable: %v", engine, err)
		}
		if bytes.Contains(raw, []byte("iptables ")) || bytes.Contains(raw, []byte("nft add ")) {
			t.Fatal("rule artifact contains live containment command")
		}
	}
	for _, engine := range []string{"", "../manifest.json", "response", "mcp"} {
		if _, err := Rules(engine); err == nil {
			t.Fatalf("arbitrary rule path %q allowed", engine)
		}
	}
	suricata, _ := Rules("suricata")
	if !strings.Contains(string(suricata), "sid:9900001;") {
		t.Fatal("expected source-derived signature missing")
	}
}

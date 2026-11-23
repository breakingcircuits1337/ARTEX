package defense

import (
	"testing"
	"time"
)

func armedEmergencyTest(t *testing.T) EmergencyConfig {
	t.Helper()
	t.Setenv("ARTEX_MODE", "defense")
	t.Setenv("ARTEX_AUTO_CONTAIN_MODE", "simulate")
	t.Setenv("ARTEX_AUTO_CONTAIN_PROTECTED_CIDRS", "192.0.2.0/24,10.4.0.0/16")
	cfg, err := LoadEmergencyConfig()
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestEmergencyOffByDefault(t *testing.T) {
	t.Setenv("ARTEX_MODE", "defense")
	t.Setenv("ARTEX_AUTO_CONTAIN_MODE", "")
	t.Setenv("ARTEX_AUTO_CONTAIN_PROTECTED_CIDRS", "")
	cfg, err := LoadEmergencyConfig()
	if err != nil || cfg.Mode != EmergencyOff {
		t.Fatalf("config=%+v err=%v", cfg, err)
	}
}

func TestEmergencyScopeAndExemptions(t *testing.T) {
	cfg := armedEmergencyTest(t)
	t.Setenv("ARTEX_AUTO_CONTAIN_EXEMPT_CIDRS", "8.8.8.0/24")
	cfg, err := LoadEmergencyConfig()
	if err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{
		{"10.1.2.3", "192.0.2.8"}, {"127.0.0.1", "192.0.2.8"},
		{"192.168.1.1", "192.0.2.8"}, {"203.0.113.4", "192.0.2.8"},
		{"8.8.8.8", "192.0.2.8"}, {"1.1.1.1", "8.8.8.8"},
		{"1.1.1.1", "not-a-destination"}, {"1.1.1.1", "10.4.0.3"},
	} {
		src, dst := pair[0], pair[1]
		if ok := cfg.EligibleIP(src, dst); src == "1.1.1.1" && dst == "10.4.0.3" {
			if !ok {
				t.Error("authorized destination incorrectly blocked")
			}
		} else if ok {
			t.Errorf("unsafe candidate source=%s dest=%s", src, dst)
		}
	}
	if !cfg.EligibleIP("1.1.1.1", "192.0.2.8") {
		t.Fatal("valid public source and protected destination was rejected")
	}
}

func TestEmergencyRequiresEvidence(t *testing.T) {
	cfg := armedEmergencyTest(t)
	now := time.Now().UTC()
	event := SecurityEvent{
		Source: "suricata", Kind: "network", Action: "alert",
		SrcIP: "1.1.1.1", DstIP: "192.0.2.22",
		Signature: "critical payload", Severity: 9,
		VendorAlert: true, ObservedAt: now,
	}
	for _, tc := range []struct {
		event SecurityEvent
		count int
		valid bool
	}{
		{event, 2, false},
		{event, 3, true},
		{SecurityEvent{
			Source: "generic", Kind: event.Kind, Action: event.Action,
			SrcIP: event.SrcIP, DstIP: event.DstIP, Signature: event.Signature,
			Severity: 9, VendorAlert: true, ObservedAt: now,
		}, 3, false},
		{SecurityEvent{
			Source: event.Source, Kind: event.Kind, Action: event.Action,
			SrcIP: event.SrcIP, DstIP: event.DstIP, Signature: event.Signature,
			Severity: 9, VendorAlert: true, ObservedAt: now.Add(-time.Hour),
		}, 3, false},
	} {
		_, ok := cfg.Decide(tc.event, now, tc.count, 0)
		if ok != tc.valid {
			t.Errorf("count=%d source=%s got=%v want=%v", tc.count, tc.event.Source, ok, tc.valid)
		}
	}
	wazuh := SecurityEvent{
		Source: "wazuh", Kind: "authentication", Outcome: "failure",
		SrcIP: "1.1.1.1", DstIP: "192.0.2.22",
		Username: "alice", ObservedAt: now,
	}
	if _, ok := cfg.Decide(wazuh, now, 0, 11); ok {
		t.Fatal("contained at insufficient account count")
	}
	if _, ok := cfg.Decide(wazuh, now, 0, 12); !ok {
		t.Fatal("did not contain corroborated account spray")
	}
}

func TestEmergencyInvalidConfigurationFailsClosed(t *testing.T) {
	t.Setenv("ARTEX_MODE", "defense")
	t.Setenv("ARTEX_AUTO_CONTAIN_MODE", "nftables")
	t.Setenv("ARTEX_AUTO_CONTAIN_PROTECTED_CIDRS", "")
	if _, err := LoadEmergencyConfig(); err == nil {
		t.Fatal("missing scope did not fail")
	}
	t.Setenv("ARTEX_AUTO_CONTAIN_PROTECTED_CIDRS", "invalid-cidr")
	if _, err := LoadEmergencyConfig(); err == nil {
		t.Fatal("invalid CIDR did not fail")
	}
	t.Setenv("ARTEX_AUTO_CONTAIN_PROTECTED_CIDRS", "192.0.2.0/24")
	t.Setenv("ARTEX_AUTO_CONTAIN_TTL_SECONDS", "3600")
	if _, err := LoadEmergencyConfig(); err == nil {
		t.Fatal("unbounded duration accepted")
	}
	t.Setenv("ARTEX_AUTO_CONTAIN_TTL_SECONDS", "")
	t.Setenv("ARTEX_MODE", "pentest")
	if _, err := LoadEmergencyConfig(); err == nil {
		t.Fatal("armed policy accepted in offensive mode")
	}
}

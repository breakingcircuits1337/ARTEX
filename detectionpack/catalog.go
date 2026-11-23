// Package detectionpack publishes static, curated, alert-only defensive
// signatures. It does not load signatures into a sensor or execute a scanner.
package detectionpack

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

//go:embed manifest.json suricata/artex-alert-only.rules yara/artex-alert-only.yar
var assets embed.FS

const (
	SuricataRulesPath = "suricata/artex-alert-only.rules"
	YARARulesPath = "yara/artex-alert-only.yar"
)

type Rule struct {
	Engine string `json:"engine"`
	ID string `json:"id"`
	Name string `json:"name"`
	Severity string `json:"severity"`
	FalsePositiveRisk string `json:"false_positive_risk"`
	Limitations string `json:"limitations"`
	OperatorInstallRequired bool `json:"operator_install_required"`
	AutoContainmentEligible bool `json:"auto_containment_eligible"`
}

type QuarantinedRule struct {
	Engine string `json:"engine"`
	ID string `json:"id"`
	Reason string `json:"reason"`
}

type Manifest struct {
	Name string `json:"name"`
	Version string `json:"version"`
	SourceArchive string `json:"source_archive"`
	SourceLicense string `json:"source_license"`
	Policy string `json:"policy"`
	DefaultDeployed bool `json:"default_deployed"`
	ExecutionEnabled bool `json:"execution_enabled"`
	AutonomousContainmentEnabled bool `json:"autonomous_containment_enabled"`
	RuleCount int `json:"rule_count"`
	QuarantinedCount int `json:"quarantined_count"`
	Rules []Rule `json:"rules"`
	Quarantined []QuarantinedRule `json:"quarantined"`
}

// Catalog parses the embedded manifest. No user-controlled paths, databases,
// rule expressions, or remote endpoints are loaded by this package.
func Catalog() (Manifest, error) {
	var m Manifest
	content, err := assets.ReadFile("manifest.json")
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(content, &m); err != nil {
		return m, err
	}
	return m, nil
}

// Rules returns raw detection-only content for human installation on a
// separately managed sensor. A caller cannot select arbitrary paths.
func Rules(engine string) ([]byte, error) {
	switch engine {
	case "suricata":
		return assets.ReadFile(SuricataRulesPath)
	case "yara":
		return assets.ReadFile(YARARulesPath)
	default:
		return nil, errors.New("unknown detection engine")
	}
}

var (
	sidPattern = regexp.MustCompile(`\bsid:([0-9]+);`)
	yaraPattern = regexp.MustCompile(`(?m)^rule\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{`)
	actionPattern = regexp.MustCompile(`(?m)^(alert|drop|reject|pass|rejectsrc|rejectdst|rejectboth)\s+`)
)

// Validate checks pack integrity and guarantees that no enforce/response
// directives are distributed. Native Suricata/YARA syntax tests run in CI.
func Validate() error {
	m, err := Catalog()
	if err != nil { return err }
	if m.Name == "" || m.Version == "" || m.SourceArchive == "" ||
		m.Policy != "alert_only" || m.DefaultDeployed ||
		m.ExecutionEnabled || m.AutonomousContainmentEnabled {
		return errors.New("invalid or unsafe detection pack manifest")
	}
	if len(m.Rules) != m.RuleCount || len(m.Quarantined) != m.QuarantinedCount {
		return errors.New("manifest rule counts do not match catalog")
	}
	seen := map[string]bool{}
	selected := map[string]bool{}
	for _, r := range m.Rules {
		if r.Engine != "suricata" && r.Engine != "yara" {
			return fmt.Errorf("unknown catalog engine %q", r.Engine)
		}
		key := r.Engine + ":" + r.ID
		if r.ID == "" || r.Name == "" || r.Limitations == "" ||
			r.Severity == "" || r.FalsePositiveRisk == "" ||
			!r.OperatorInstallRequired || r.AutoContainmentEligible || seen[key] {
			return fmt.Errorf("invalid, duplicated, or auto-active detection %q", key)
		}
		seen[key] = true
		selected[key] = true
	}
	for _, r := range m.Quarantined {
		key := r.Engine + ":" + r.ID
		if r.Reason == "" || r.ID == "" || seen[key] {
			return fmt.Errorf("invalid quarantine record %q", key)
		}
		seen[key] = true
	}
	suricata, err := Rules("suricata")
	if err != nil { return err }
	var counted int
	for _, line := range strings.Split(string(suricata), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") { continue }
		matches := actionPattern.FindStringSubmatch(line)
		if len(matches) == 0 || matches[1] != "alert" {
			return fmt.Errorf("non-alert Suricata rule or unrecognized directive: %q", line)
		}
		ids := sidPattern.FindStringSubmatch(line)
		if len(ids) != 2 || !selected["suricata:"+ids[1]] {
			return fmt.Errorf("Suricata SID missing from approved catalog")
		}
		delete(selected, "suricata:"+ids[1])
		counted++
	}
	yara, err := Rules("yara")
	if err != nil { return err }
	for _, match := range yaraPattern.FindAllStringSubmatch(string(yara), -1) {
		if !selected["yara:"+match[1]] {
			return fmt.Errorf("YARA rule %q missing from approved catalog", match[1])
		}
		delete(selected, "yara:"+match[1])
		counted++
	}
	if counted != m.RuleCount || len(selected) != 0 {
		return fmt.Errorf("pack sources and catalog disagree: %d rules counted, %d unmatched", counted, len(selected))
	}
	return nil
}

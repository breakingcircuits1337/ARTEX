// Package detectionpack publishes static, curated, alert-only defensive
// signatures. It never loads a rule into a sensor or executes a scanner.
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
	YARARulesPath     = "yara/artex-alert-only.yar"
)

type Rule struct {
	Engine                  string `json:"engine"`
	ID                      string `json:"id"`
	Name                    string `json:"name"`
	Severity                string `json:"severity"`
	FalsePositiveRisk       string `json:"false_positive_risk"`
	Limitations             string `json:"limitations"`
	OperatorInstallRequired bool   `json:"operator_install_required"`
	AutoContainmentEligible bool   `json:"auto_containment_eligible"`
}

type QuarantinedRule struct {
	Engine string `json:"engine"`
	ID     string `json:"id"`
	Reason string `json:"reason"`
}

type Manifest struct {
	Name                         string            `json:"name"`
	Version                      string            `json:"version"`
	SourceArchive                string            `json:"source_archive"`
	SourceLicense                string            `json:"source_license"`
	Policy                       string            `json:"policy"`
	DefaultDeployed              bool              `json:"default_deployed"`
	ExecutionEnabled             bool              `json:"execution_enabled"`
	AutonomousContainmentEnabled bool              `json:"autonomous_containment_enabled"`
	RuleCount                    int               `json:"rule_count"`
	QuarantinedCount             int               `json:"quarantined_count"`
	Rules                        []Rule            `json:"rules"`
	Quarantined                  []QuarantinedRule `json:"quarantined"`
}

// Catalog parses immutable embedded metadata, not remote URLs or user files.
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

// LookupRule accepts exactly a known curated name, not arbitrary code or
// commands. The result is an observation label, never enforcement permission.
func LookupRule(engine, id string) (Rule, bool) {
	m, err := Catalog()
	if err != nil {
		return Rule{}, false
	}
	for _, r := range m.Rules {
		if r.Engine == engine && r.ID == id {
			return r, true
		}
	}
	return Rule{}, false
}

// Rules exposes two fixed files for operator-managed sensor installation.
// A caller cannot select a path supplied by an attacker.
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
	sidPattern    = regexp.MustCompile(`\bsid:([0-9]+);`)
	yaraPattern   = regexp.MustCompile(`(?m)^rule\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{`)
	actionPattern = regexp.MustCompile(`(?m)^(alert|drop|reject|pass|rejectsrc|rejectdst|rejectboth)\s+`)
)

// Validate checks the embedded inventory and ensures only alert directives
// are distributed. Actual Suricata/YARA syntax tests run separately in CI.
func Validate() error {
	m, err := Catalog()
	if err != nil {
		return err
	}
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
	for _, rule := range m.Rules {
		if rule.Engine != "suricata" && rule.Engine != "yara" {
			return fmt.Errorf("unknown catalog engine %q", rule.Engine)
		}
		key := rule.Engine + ":" + rule.ID
		if rule.ID == "" || rule.Name == "" || rule.Limitations == "" ||
			rule.Severity == "" || rule.FalsePositiveRisk == "" ||
			!rule.OperatorInstallRequired || rule.AutoContainmentEligible || seen[key] {
			return fmt.Errorf("invalid, duplicate, or auto-active detection %q", key)
		}
		seen[key] = true
		selected[key] = true
	}
	for _, rule := range m.Quarantined {
		key := rule.Engine + ":" + rule.ID
		if rule.Reason == "" || rule.ID == "" || seen[key] {
			return fmt.Errorf("invalid quarantine record %q", key)
		}
		seen[key] = true
	}
	suricata, err := Rules("suricata")
	if err != nil {
		return err
	}
	var counted int
	for _, line := range strings.Split(string(suricata), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		matches := actionPattern.FindStringSubmatch(line)
		if len(matches) == 0 || matches[1] != "alert" {
			return fmt.Errorf("non-alert Suricata directive: %q", line)
		}
		ids := sidPattern.FindStringSubmatch(line)
		if len(ids) != 2 || !selected["suricata:"+ids[1]] {
			return errors.New("unreviewed or duplicate Suricata SID")
		}
		delete(selected, "suricata:"+ids[1])
		counted++
	}
	yara, err := Rules("yara")
	if err != nil {
		return err
	}
	for _, match := range yaraPattern.FindAllStringSubmatch(string(yara), -1) {
		if !selected["yara:"+match[1]] {
			return fmt.Errorf("unreviewed or duplicate YARA rule %q", match[1])
		}
		delete(selected, "yara:"+match[1])
		counted++
	}
	if counted != m.RuleCount || len(selected) != 0 {
		return fmt.Errorf("source/manifest mismatch: %d counted, %d unmatched", counted, len(selected))
	}
	return nil
}

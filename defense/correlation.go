package defense

import (
	"errors"
	"net/netip"
	"regexp"
	"strings"
	"unicode"
)

// ObservedIndicator is a bounded, normalized observation from an existing
// security event. It is NOT an attacker identity or malicious IOC verdict.
type ObservedIndicator struct {
	Type  string `json:"type"`
	Value string `json:"value"`
	Role  string `json:"role"`
}

var (
	attackTechniqueFormat = regexp.MustCompile(`^T[0-9]{4}(\.[0-9]{3})?$`)
	attackTacticFormat    = regexp.MustCompile(`^TA[0-9]{4}$`)
)

func cleanObservedText(value string, maxBytes int) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maxBytes {
		return ""
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return ""
		}
	}
	return value
}

// CaseIndicators only derives directly observed src/dst IPs, a reported host,
// and a sensor signature. It never guesses attacker infrastructure, hashes,
// usernames, technique IDs or maliciousness from free text.
func CaseIndicators(srcIP, dstIP, host, signature string) []ObservedIndicator {
	var out []ObservedIndicator
	for _, p := range []struct {
		value string
		role  string
	}{{srcIP, "source_ip"}, {dstIP, "destination_ip"}} {
		addr, err := netip.ParseAddr(strings.TrimSpace(p.value))
		if err != nil || addr.Zone() != "" {
			continue
		}
		out = append(out, ObservedIndicator{Type: "ip", Value: addr.Unmap().String(), Role: p.role})
	}
	host = strings.ToLower(cleanObservedText(host, 256))
	// A log-reported host is an untrusted label; do not follow, resolve,
	// network-connect or normalize it into an operator-authorized target.
	if host != "" {
		out = append(out, ObservedIndicator{Type: "host", Value: host, Role: "host"})
	}
	signature = cleanObservedText(signature, 256)
	if signature != "" {
		out = append(out, ObservedIndicator{Type: "signature", Value: signature, Role: "sensor_signature"})
	}
	return out
}

// ValidateATTACKHypothesis only validates identifier syntax, not existence in
// the ATT&CK catalog or evidence of actual attacker behavior. Mapping remains
// analyst-provided, evidence-linked, and cannot be treated as confirmation.
func ValidateATTACKHypothesis(techniqueID, tacticID string, confidence int, reason string) (string, error) {
	if !attackTechniqueFormat.MatchString(techniqueID) {
		return "", errors.New("invalid ATT&CK technique ID format")
	}
	if tacticID != "" && !attackTacticFormat.MatchString(tacticID) {
		return "", errors.New("invalid ATT&CK tactic ID format")
	}
	if confidence < 1 || confidence > 90 {
		return "", errors.New("mapping confidence must be 1..90, never claimed certainty")
	}
	validated, err := ValidateReason(reason)
	if err != nil {
		return "", err
	}
	return validated, nil
}

// KnownRuleATTACKHint does not assert proof of the behavior described by the
// mapping. Only explicit built-in behavioral rules receive a low-confidence
// suggestion; imported/curated signature names never auto-map.
func KnownRuleATTACKHint(ruleID string) (technique, tactic string, ok bool) {
	if ruleID == "password_spray_v1" {
		return "T1110.003", "TA0006", true // Password Spraying / Credential Access
	}
	return "", "", false
}

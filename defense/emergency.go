package defense

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

// EmergencyMode is deliberately independent of the agent/LLM and its prompts.
type EmergencyMode string

const (
	EmergencyOff      EmergencyMode = "off"
	EmergencySimulate EmergencyMode = "simulate"
	EmergencyNFT      EmergencyMode = "nftables"
)

// EmergencyConfig is operator-supplied, bounded and fail-closed. An empty
// destination scope cannot be interpreted as "all networks".
type EmergencyConfig struct {
	Mode           EmergencyMode
	Protected      []netip.Prefix
	Exempt         []netip.Prefix
	TTL            time.Duration
	MaxActive      int
	MaxPerHour     int
	Freshness      time.Duration
	AllowedSignatures []string
}

var reservedSources = []string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
	"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
	"192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15",
	"198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
}

func parseEmergencyCIDRs(raw string) ([]netip.Prefix, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	items := strings.Split(raw, ",")
	if len(items) > 64 {
		return nil, errors.New("emergency CIDR list exceeds 64 networks")
	}
	result := make([]netip.Prefix, 0, len(items))
	for _, item := range items {
		p, err := netip.ParsePrefix(strings.TrimSpace(item))
		if err != nil || !p.Addr().Is4() {
			return nil, fmt.Errorf("invalid emergency IPv4 CIDR %q", item)
		}
		result = append(result, p.Masked())
	}
	return result, nil
}

func envInt(name string, fallback, low, high int) (int, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < low || n > high {
		return 0, fmt.Errorf("%s must be %d..%d", name, low, high)
	}
	return n, nil
}

// LoadEmergencyConfig must be evaluated at startup and on each enforcement
// request. Unknown modes and missing scopes fail closed (never widen scope).
func LoadEmergencyConfig() (EmergencyConfig, error) {
	cfg := EmergencyConfig{Mode: EmergencyMode(strings.ToLower(strings.TrimSpace(os.Getenv("ARTEX_AUTO_CONTAIN_MODE"))))}
	if cfg.Mode == "" {
		cfg.Mode = EmergencyOff
	}
	switch cfg.Mode {
	case EmergencyOff, EmergencySimulate, EmergencyNFT:
	default:
		return EmergencyConfig{}, fmt.Errorf("unsupported ARTEX_AUTO_CONTAIN_MODE %q", cfg.Mode)
	}
	var err error
	cfg.Protected, err = parseEmergencyCIDRs(os.Getenv("ARTEX_AUTO_CONTAIN_PROTECTED_CIDRS"))
	if err != nil {
		return EmergencyConfig{}, err
	}
	cfg.Exempt, err = parseEmergencyCIDRs(os.Getenv("ARTEX_AUTO_CONTAIN_EXEMPT_CIDRS"))
	if err != nil {
		return EmergencyConfig{}, err
	}
	seconds, err := envInt("ARTEX_AUTO_CONTAIN_TTL_SECONDS", 120, 30, 300)
	if err != nil {
		return EmergencyConfig{}, err
	}
	cfg.TTL = time.Duration(seconds) * time.Second
	cfg.MaxActive, err = envInt("ARTEX_AUTO_CONTAIN_MAX_ACTIVE", 20, 1, 50)
	if err != nil {
		return EmergencyConfig{}, err
	}
	cfg.MaxPerHour, err = envInt("ARTEX_AUTO_CONTAIN_MAX_PER_HOUR", 50, 1, 200)
	if err != nil {
		return EmergencyConfig{}, err
	}
	cfg.Freshness = 30 * time.Second
	sigs := strings.TrimSpace(os.Getenv("ARTEX_AUTO_CONTAIN_SURICATA_SIGNATURES"))
	if sigs != "" {
		parts := strings.Split(sigs, ",")
		if len(parts) > 32 {
			return EmergencyConfig{}, errors.New("emergency Suricata allowlist exceeds 32 signatures")
		}
		for _, part := range parts {
			sig := strings.TrimSpace(part)
			if len(sig) < 3 || len(sig) > 256 {
				return EmergencyConfig{}, errors.New("emergency Suricata signature must be 3..256 bytes")
			}
			cfg.AllowedSignatures = append(cfg.AllowedSignatures, sig)
		}
	}
	if cfg.Mode != EmergencyOff && len(cfg.Protected) == 0 {
		return EmergencyConfig{}, errors.New("emergency containment needs explicit protected destination IPv4 CIDRs")
	}
	if cfg.Mode != EmergencyOff && !Restricted() {
		return EmergencyConfig{}, errors.New("emergency containment requires ARTEX_MODE=defense")
	}
	return cfg, nil
}

func containsPrefix(prefixes []netip.Prefix, a netip.Addr) bool {
	for _, p := range prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// EligibleIP returns false for all reserved/private, infrastructure or
// explicitly exempt addresses. Only one exact public IPv4 host can be blocked.
// This policy is deliberately conservative for critical infrastructure.
func (cfg EmergencyConfig) EligibleIP(source, destination string) bool {
	src, err := netip.ParseAddr(source)
	if err != nil || !src.Is4() || !src.IsGlobalUnicast() || src.IsPrivate() {
		return false
	}
	for _, raw := range reservedSources {
		if netip.MustParsePrefix(raw).Contains(src) {
			return false
		}
	}
	dst, err := netip.ParseAddr(destination)
	if err != nil || !dst.Is4() || !containsPrefix(cfg.Protected, dst) {
		return false
	}
	if containsPrefix(cfg.Exempt, src) || containsPrefix(cfg.Protected, src) {
		return false
	}
	return true
}

// Only explicitly operator-reviewed Suricata signatures may trigger live
// containment. An unspecified allowlist means no automatic IDS response.
func (cfg EmergencyConfig) TrustedSignature(signature string) bool {
	for _, approved := range cfg.AllowedSignatures {
		if signature == approved {
			return true
		}
	}
	return false
}

// EmergencyDecision is a preauthorized deterministic rule, not an LLM
// recommendation. The caller supplies counts from stored, distinct telemetry.
type EmergencyDecision struct {
	Rule   string
	Reason string
}

// Decide requires fresh observations and corroboration BEFORE an emergency
// action can be staged. Off and unknown states cannot result in containment.
func (cfg EmergencyConfig) Decide(event SecurityEvent, now time.Time, repeatedAlerts, distinctAccounts int) (EmergencyDecision, bool) {
	if cfg.Mode == EmergencyOff || !cfg.EligibleIP(event.SrcIP, event.DstIP) {
		return EmergencyDecision{}, false
	}
	age := now.Sub(event.ObservedAt)
	if age < -5*time.Second || age > cfg.Freshness {
		return EmergencyDecision{}, false
	}
	if event.Source == "suricata" && event.Kind == "network" &&
		event.Action == "alert" && event.VendorAlert &&
		event.Severity >= 9 && cfg.TrustedSignature(event.Signature) && repeatedAlerts >= 3 {
		return EmergencyDecision{
			Rule:   "repeated_critical_ids_v1",
			Reason: "Three or more matching critical Suricata alerts for an authorized destination within ten seconds",
		}, true
	}
	if event.Source == "wazuh" && event.Kind == "authentication" &&
		event.Outcome == "failure" && event.Username != "" && distinctAccounts >= 12 {
		return EmergencyDecision{
			Rule:   "active_password_spray_v1",
			Reason: "Twelve or more distinct failed account names from one source to an authorized destination within sixty seconds",
		}, true
	}
	return EmergencyDecision{}, false
}

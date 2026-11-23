package defense

// AdvisorySafetyGate is a deterministic, *limited* output-policy check.
// It cannot prove truth or stop paraphrased instructions. Rejecting unsafe
// output prevents known high-risk hallucinations from being persisted.
// The existing no-tool boundary and mandatory human review remain essential.
import (
	"errors"
	"regexp"
	"strings"
)

var aiOutputSensitivePattern = regexp.MustCompile("(?i)(?:\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b|\\b[a-z0-9._%+\\-]+@[a-z0-9.\\-]+\\.[a-z]{2,}\\b)")
var aiActionDirectivePattern = regexp.MustCompile("(?i)\\b(?:block|isolate|quarantine|disable|revoke|delete|execute|nftables|iptables|sudo)\\b|\\brun\\s+(?:a\\s+)?(?:shell|command|script)\\b|\\brm\\s+-rf\\b")
var aiOverconfidencePattern = regexp.MustCompile("(?i)\\b(?:confirmed\\s+(?:breach|compromise|intrusion)|definitively\\s+malicious|proven\\s+attack|known\\s+attacker)\\b")

// ValidateAIAdvisorySafety is a fail-closed heuristic on all explanatory text.
// These patterns deliberately reject some benign quotations or negations: the
// model can instead use ordinary review language. Semantic evasion remains
// possible; this is not a policy engine or compromise classifier.
func ValidateAIAdvisorySafety(text string) error {
	if aiOutputSensitivePattern.MatchString(text) {
		return errors.New("AI output includes an unexpected address or identifier")
	}
	if aiActionDirectivePattern.MatchString(text) {
		return errors.New("AI output includes a command or enforcement directive")
	}
	if aiOverconfidencePattern.MatchString(text) {
		return errors.New("AI output asserts unsupported confirmed compromise")
	}
	return nil
}

// ValidateAIAdvisoryGrounding checks a limited category/evidence invariant:
// model-defined corroboration must reference an additional case observation.
// Referencing an event is NOT proof that it actually corroborates an incident.
func ValidateAIAdvisoryGrounding(out AIAdvice, refs map[string]int64) error {
	if !strings.Contains(strings.ToLower(out.Summary), "unverified") {
		return errors.New("AI summary must explicitly mark evidence unverified")
	}
	if err := ValidateAIAdvisorySafety(out.Summary); err != nil {
		return err
	}
	for _, f := range out.Findings {
		if err := ValidateAIAdvisorySafety(f.Explanation); err != nil {
			return err
		}
		if f.Category == "corroboration" && (len(refs) < 2 || f.EvidenceRef == "ev1") {
			return errors.New("AI corroboration requires a second cited case event")
		}
	}
	return nil
}

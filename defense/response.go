package defense

import (
	"errors"
	"strings"
	"unicode/utf8"
)

const (
	CaseOpen          = "open"
	CaseInvestigating = "investigating"
	CaseResolved      = "resolved"
	CaseDismissed     = "dismissed"

	ResponsePending   = "pending"
	ResponseApproved  = "approved"
	ResponseRejected  = "rejected"
	ResponseSimulated = "simulated"
)

// CaseTransition is the explicit triage lifecycle. Terminal states cannot be
// reopened without creating a new security alert and new case.
func CaseTransition(from, to string) bool {
	switch from {
	case CaseOpen:
		return to == CaseInvestigating || to == CaseDismissed
	case CaseInvestigating:
		return to == CaseResolved || to == CaseDismissed
	default:
		return false
	}
}

// ActiveCase identifies states in which an operator may propose or approve a
// manual response. Closing a case requires disposition of pending proposals.
func ActiveCase(status string) bool {
	return status == CaseOpen || status == CaseInvestigating
}

// ResponseTransition is deliberately one-way. Approving a proposal never
// executes it; only a separate, explicit dry-run transition is supported.
func ResponseTransition(from, to string) bool {
	return from == ResponsePending && (to == ResponseApproved || to == ResponseRejected) ||
		from == ResponseApproved && to == ResponseSimulated
}

// Playbook is a fixed, reviewable set of human operating instructions.
// Instructions never contain target-supplied commands or executable payloads.
type Playbook struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Risk        string   `json:"risk"`
	Explanation string   `json:"explanation"`
	Steps       []string `json:"steps"`
}

var playbooks = []Playbook{
	{
		ID: "review_network_block", Name: "Review a proposed network block",
		Risk:        "high",
		Explanation: "A firewall change may interrupt production traffic, especially on OT or control networks. This workflow is advisory only.",
		Steps: []string{
			"Verify incident evidence, network ownership, and exact source/destination scope.",
			"Determine affected applications, critical infrastructure dependencies, maintenance windows, and rollback owner.",
			"Obtain change-control and safety approval outside ARTEX before any external change.",
			"If the operator later changes an external firewall, capture change ID, verification, and rollback evidence in the separate change-control system.",
		},
	},
	{
		ID: "review_identity_controls", Name: "Review identity containment",
		Risk:        "high",
		Explanation: "Account disablement and credential resets may disrupt legitimate access. This workflow cannot alter an identity provider.",
		Steps: []string{
			"Correlate authentication signals against the identity provider's authoritative logs.",
			"Check for service accounts, emergency access, privileged users, false positives, and business-critical dependencies.",
			"Obtain identity owner approval and a restoration plan before any external access change.",
			"Record the operator's verification and change-control ID outside ARTEX.",
		},
	},
	{
		ID: "review_endpoint_isolation", Name: "Review endpoint isolation",
		Risk:        "critical",
		Explanation: "Isolating industrial, medical, or critical infrastructure endpoints can cause unacceptable availability or safety impacts. This workflow cannot call an EDR.",
		Steps: []string{
			"Confirm host identity, asset criticality, detection evidence, and whether the endpoint is OT/safety-critical.",
			"Consult the system owner and site safety officer before any disruptive intervention.",
			"Develop an alternative monitoring strategy and restoration procedure.",
			"Perform any approved action only in an externally controlled system with independent human authorization.",
		},
	},
	{
		ID: "collect_additional_evidence", Name: "Review and collect additional evidence",
		Risk:        "low",
		Explanation: "A passive investigation plan; it never starts a remote collection job.",
		Steps: []string{
			"Review the linked alert, source event identifier, and any matched assets.",
			"Determine which existing authorized logs could confirm or refute the signal.",
			"Document missing evidence, business context, hypotheses, and counterevidence.",
			"Request any additional collection through the authorized external logging team.",
		},
	},
}

// Playbooks returns defensive response templates with no arbitrary shell or
// network-action parameters. Keep this list small and explicitly reviewed.
func Playbooks() []Playbook {
	out := make([]Playbook, len(playbooks))
	for i, p := range playbooks {
		out[i] = p
		out[i].Steps = append([]string(nil), p.Steps...)
	}
	return out
}

// LookupPlaybook only accepts hard-coded templates.
func LookupPlaybook(id string) (Playbook, bool) {
	for _, p := range playbooks {
		if p.ID == id {
			return p, true
		}
	}
	return Playbook{}, false
}

// ValidateReason rejects empty, oversized or control-containing audit notes.
// The same bounds apply at every state-changing endpoint.
func ValidateReason(reason string) (string, error) {
	reason = strings.TrimSpace(reason)
	if len(reason) < 12 || len(reason) > 1200 || !utf8.ValidString(reason) {
		return "", errors.New("reason must contain 12..1200 valid UTF-8 bytes")
	}
	for _, ch := range reason {
		if ch < 32 && ch != '\n' && ch != '\t' {
			return "", errors.New("reason contains prohibited control characters")
		}
	}
	return reason, nil
}

// Technique is background context, not an assertion that ATT&CK techniques
// were actually observed or that the incident is confirmed.
func Technique(ruleID string) string {
	if ruleID == "password_spray_v1" {
		return "T1110.003"
	}
	return ""
}

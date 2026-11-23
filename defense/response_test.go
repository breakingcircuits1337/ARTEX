package defense

import (
	"strings"
	"testing"
)

func TestCaseTransitions(t *testing.T) {
	for _, tc := range []struct {
		from, to string
		want     bool
	}{
		{CaseOpen, CaseInvestigating, true},
		{CaseOpen, CaseDismissed, true},
		{CaseOpen, CaseResolved, false},
		{CaseInvestigating, CaseResolved, true},
		{CaseInvestigating, CaseDismissed, true},
		{CaseResolved, CaseOpen, false},
		{CaseDismissed, CaseInvestigating, false},
		{CaseOpen, CaseOpen, false},
	} {
		if got := CaseTransition(tc.from, tc.to); got != tc.want {
			t.Errorf("CaseTransition(%q,%q)=%v, want %v", tc.from, tc.to, got, tc.want)
		}
	}
}

func TestResponseTransitions(t *testing.T) {
	for _, tc := range []struct {
		from, to string
		want     bool
	}{
		{ResponsePending, ResponseApproved, true},
		{ResponsePending, ResponseRejected, true},
		{ResponseApproved, ResponseSimulated, true},
		{ResponsePending, ResponseSimulated, false},
		{ResponseApproved, ResponseRejected, false},
		{ResponseRejected, ResponseApproved, false},
		{ResponseSimulated, ResponseApproved, false},
	} {
		if got := ResponseTransition(tc.from, tc.to); got != tc.want {
			t.Errorf("ResponseTransition(%q,%q)=%v, want %v", tc.from, tc.to, got, tc.want)
		}
	}
}

func TestFixedManualPlaybooks(t *testing.T) {
	ps := Playbooks()
	if len(ps) != 4 {
		t.Fatalf("got %d playbooks", len(ps))
	}
	for _, p := range ps {
		found, ok := LookupPlaybook(p.ID)
		if !ok || found.ID != p.ID || len(p.Steps) == 0 {
			t.Errorf("invalid playbook %+v", p)
		}
	}
	ps[0].Steps[0] = "injected"
	next, _ := LookupPlaybook(ps[0].ID)
	if next.Steps[0] == "injected" {
		t.Fatal("playbook list was mutated")
	}
	if _, ok := LookupPlaybook("run_shell"); ok {
		t.Fatal("unreviewed playbook permitted")
	}
}

func TestReasonValidation(t *testing.T) {
	for _, input := range []string{"", "short", strings.Repeat("a", 1201), "long enough\x00bad"} {
		if _, err := ValidateReason(input); err == nil {
			t.Errorf("accepted invalid reason %q", input)
		}
	}
	valid, err := ValidateReason("  Reviewed source evidence and owner scope.  ")
	if err != nil || valid != "Reviewed source evidence and owner scope." {
		t.Fatalf("valid reason=%q err=%v", valid, err)
	}
}

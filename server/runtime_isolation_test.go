package server

import (
	"strings"
	"testing"
)

func TestRuntimeIsolationFlagValues(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  bool
		bad   bool
	}{
		{"", false, false},
		{"0", false, false},
		{"off", false, false},
		{"no", false, false},
		{"FALSE", false, false},
		{"1", true, false},
		{"true", true, false},
		{"YES", true, false},
		{" on ", true, false},
		{"enable-everything", false, true},
	} {
		t.Run("value-"+tc.value, func(t *testing.T) {
			t.Setenv("ARTEX_TEST_RUNTIME_FLAG", tc.value)
			got, err := runtimeIsolationFlag("ARTEX_TEST_RUNTIME_FLAG")
			if (err != nil) != tc.bad || (err == nil && got != tc.want) {
				t.Fatalf("value %q: got %v err %v; want %v bad=%v", tc.value, got, err, tc.want, tc.bad)
			}
		})
	}
}

func TestValidateRuntimeIsolationRequiresSeparateExecutor(t *testing.T) {
	t.Setenv("ARTEX_REQUIRE_EXEC_ISOLATION", "1")
	t.Setenv("ARTEX_REQUIRE_USERNS", "0")
	if err := ValidateRuntimeIsolation(ExecPrivilege{}); err == nil || !strings.Contains(err.Error(), "unavailable or disabled") {
		t.Fatalf("disabled drop accepted: %v", err)
	}
	if err := ValidateRuntimeIsolation(ExecPrivilege{Enabled: true, UID: DefaultExecUID, GID: DefaultExecGID}); err != nil {
		t.Fatalf("separate executor rejected: %v", err)
	}
}

func TestValidateRuntimeIsolationUserNSRequiresExecutor(t *testing.T) {
	t.Setenv("ARTEX_REQUIRE_EXEC_ISOLATION", "0")
	t.Setenv("ARTEX_REQUIRE_USERNS", "1")
	err := ValidateRuntimeIsolation(ExecPrivilege{})
	if err == nil || !strings.Contains(err.Error(), "requires an enabled") {
		t.Fatalf("userns accepted without separate executor: %v", err)
	}
}

func TestValidateRuntimeIsolationRejectsInvalidValue(t *testing.T) {
	t.Setenv("ARTEX_REQUIRE_USERNS", "unexpected")
	t.Setenv("ARTEX_REQUIRE_EXEC_ISOLATION", "0")
	if err := ValidateRuntimeIsolation(ExecPrivilege{}); err == nil || !strings.Contains(err.Error(), "ARTEX_REQUIRE_USERNS") {
		t.Fatalf("invalid switch accepted: %v", err)
	}
}

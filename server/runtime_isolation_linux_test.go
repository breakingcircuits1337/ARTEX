//go:build linux

package server

import (
	"strings"
	"testing"
)

func TestCheckMappedRootUID(t *testing.T) {
	for _, tc := range []struct {
		name, mapping string
		wantFailure   bool
	}{
		{"rootless daemon mapping", "0 1000 1\n1 100000 65536\n", false},
		{"userns remap mapping", "0 165536 65536\n", false},
		{"identity host-root map", "0 0 4294967295\n", true},
		{"host-root with subsequent remap", "0 0 1\n1 100000 65536\n", true},
		{"unmapped root", "1 100001 65535\n", true},
		{"zero length", "0 1000 0\n", true},
		{"bad entry", "not-an-integer 1000 1\n", true},
		{"empty", "", true},
		{"duplicate", "0 1000 1\n0 2000 1\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkMappedRootUID(tc.mapping)
			if (err != nil) != tc.wantFailure {
				t.Fatalf("mapping %q: error=%v; want failure=%v", tc.mapping, err, tc.wantFailure)
			}
		})
	}
}

func TestValidateRuntimeIsolationUserNSFailsOnHostRoot(t *testing.T) {
	// This test does not inspect or change the host mapping. If the test
	// process runs as host-root in the initial namespace, mandatory userns
	// isolation must fail; under rootless CI the same check can succeed.
	raw, err := checkUserNamespaceRootMapping(), error(nil)
	_ = raw
	_ = err
	t.Setenv("ARTEX_REQUIRE_EXEC_ISOLATION", "1")
	t.Setenv("ARTEX_REQUIRE_USERNS", "1")
	// The result must be the real mapping check, not a silent bypass.
	priv := ExecPrivilege{Enabled: true, UID: DefaultExecUID, GID: DefaultExecGID}
	if actual := ValidateRuntimeIsolation(priv); (actual == nil) != (checkUserNamespaceRootMapping() == nil) {
		t.Fatalf("startup did not enforce the kernel mapping: %v", actual)
	}
}

func TestCheckMappedRootUIDRefusesRootful(t *testing.T) {
	if err := checkMappedRootUID("0 0 4294967295\n"); err == nil || !strings.Contains(err.Error(), "UID 0") {
		t.Fatalf("rootful host mapping accepted: %v", err)
	}
}

//go:build linux

package server

import (
	"bytes"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// Verify the kernel process-level protection without changing the test
// runner's privileges or requiring root, containers, or a live database.
// This also runs in CI where the root-only Bash/MCP probes are skipped.
func TestLockExecutorPrivilegesProbe(t *testing.T) {
	if os.Getenv("ARTEX_TEST_NO_NEW_PRIVS_CHILD") == "1" {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if err := lockExecutorPrivileges(); err != nil {
			t.Fatal(err)
		}
		name := "/proc/self/task/" + strconv.Itoa(unix.Gettid()) + "/status"
		body, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(body, []byte("NoNewPrivs:\t1\n")) {
			t.Fatalf("kernel did not enforce no_new_privs for executor: %s", strings.TrimSpace(string(body)))
		}
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestLockExecutorPrivilegesProbe$")
	cmd.Env = append(os.Environ(), "ARTEX_TEST_NO_NEW_PRIVS_CHILD=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("isolated no-new-privs probe failed: %v\n%s", err, out)
	}
}

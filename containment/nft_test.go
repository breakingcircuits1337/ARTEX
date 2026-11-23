package containment

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Fake nft checks fixed command argv and a simulated kernel-state transition.
// This test neither needs CAP_NET_ADMIN nor touches a real firewall.
func TestNFTRunnerFixedCommandBoundary(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("fake executable requires Linux")
	}
	dir := t.TempDir()
	state := filepath.Join(dir, "present")
	logPath := filepath.Join(dir, "calls")
	t.Setenv("FAKE_NFT_STATE", state)
	t.Setenv("FAKE_NFT_LOG", logPath)
	t.Setenv("PATH", dir)
	script := `#!/bin/sh
printf '%s\n' "$*" >> "$FAKE_NFT_LOG"
case "$1 $2" in
  "list set") printf 'table inet artex_emergency { set blocked_v4 { type ipv4_addr; flags timeout; }}\n'; exit 0 ;;
  "get element") test -f "$FAKE_NFT_STATE"; exit $? ;;
  "add element") /bin/touch "$FAKE_NFT_STATE"; exit $? ;;
  "delete element") /bin/rm -f "$FAKE_NFT_STATE"; exit $? ;;
esac
exit 2
`
	if err := os.WriteFile(filepath.Join(dir, "nft"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	runner := NFTRunner{}
	if err := runner.Check(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.Apply(ctx, "1.1.1.1", 60*time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(state); err != nil {
		t.Fatal("fake rule not added", err)
	}
	if err := runner.Revert(ctx, "1.1.1.1"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(state); !os.IsNotExist(err) {
		t.Fatal("fake rule not removed")
	}
	if err := runner.Apply(ctx, "10.0.0.1", 60*time.Second); err == nil {
		t.Fatal("private source accepted")
	}
	if err := runner.Apply(ctx, "1.1.1.1", 10*time.Minute); err == nil {
		t.Fatal("unbounded expiry accepted")
	}
	log, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := string(log)
	for _, operation := range []string{
		"list set inet artex_emergency blocked_v4",
		"add element inet artex_emergency blocked_v4",
		"delete element inet artex_emergency blocked_v4",
	} {
		if !strings.Contains(lines, operation) {
			t.Errorf("missing fixed nft operation %s", operation)
		}
	}
}

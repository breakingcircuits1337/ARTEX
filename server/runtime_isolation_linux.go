//go:build linux

package server

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// checkMappedRootUID verifies that UID 0 in our current Linux user namespace
// does not map to UID 0 in its parent namespace. This is an intentionally
// narrow claim: it proves a userns boundary, not that dockerd itself is
// rootless or that the host has no other privileged processes.
func checkMappedRootUID(contents string) error {
	found := false
	for _, line := range strings.Split(contents, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			return fmt.Errorf("malformed /proc/self/uid_map entry")
		}
		inner, e1 := strconv.ParseUint(fields[0], 10, 32)
		outer, e2 := strconv.ParseUint(fields[1], 10, 32)
		count, e3 := strconv.ParseUint(fields[2], 10, 32)
		if e1 != nil || e2 != nil || e3 != nil || count == 0 {
			return fmt.Errorf("invalid /proc/self/uid_map entry")
		}
		if inner == 0 {
			if found {
				return fmt.Errorf("duplicate UID 0 mapping")
			}
			found = true
			if outer == 0 {
				return fmt.Errorf("container UID 0 maps to parent UID 0; remapped root is required")
			}
		}
	}
	if !found {
		return fmt.Errorf("user namespace has no UID 0 mapping")
	}
	return nil
}

func checkUserNamespaceRootMapping() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("server must be UID 0 inside a remapped user namespace to retain separate executor credentials")
	}
	raw, err := os.ReadFile("/proc/self/uid_map")
	if err != nil {
		return fmt.Errorf("read kernel user namespace mapping: %w", err)
	}
	return checkMappedRootUID(string(raw))
}

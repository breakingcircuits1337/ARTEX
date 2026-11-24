//go:build linux

package server

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// Lock the executor against regaining privileges through setuid/setgid
// executables or file capabilities after the UID/GID switch. This is
// inherited across exec/fork and does not block authorized network access.
// When the kernel refuses this guard, the agent process must not start.
func lockExecutorPrivileges() error {
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("set no-new-privileges for agent: %w", err)
	}
	return nil
}

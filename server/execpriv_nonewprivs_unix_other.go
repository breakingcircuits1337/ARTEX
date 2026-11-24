//go:build unix && !linux

package server

// Linux PR_SET_NO_NEW_PRIVS has no direct equivalent on other Unix platforms.
// The separate executor UID/GID drop continues to apply.
func lockExecutorPrivileges() error { return nil }

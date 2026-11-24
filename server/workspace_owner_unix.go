//go:build !windows

package server

import (
	"os"
	"syscall"
)

// Replacing a file atomically must not turn an executor-owned private artifact
// into a root-owned file that the executor can no longer read. Root callers
// preserve the original UID/GID; non-root callers already own their temp file.
func workspacePreserveOwner(out *os.File, previous os.FileInfo) error {
	if os.Geteuid() != 0 {
		return nil
	}
	st, ok := previous.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	return out.Chown(int(st.Uid), int(st.Gid))
}

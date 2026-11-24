//go:build windows

package server

import "os"

// Windows ACL and owner semantics are not encoded in Unix FileMode.
func workspacePreserveOwner(_ *os.File, _ os.FileInfo) error {
	return nil
}

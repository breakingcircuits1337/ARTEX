//go:build !linux

package server

import "fmt"

func checkUserNamespaceRootMapping() error {
	return fmt.Errorf("remapped UID 0 isolation requires Linux user namespaces")
}

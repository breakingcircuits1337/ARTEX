package server

import (
	"fmt"
	"os"
	"strings"
)

// Runtime isolation is explicit and fail-closed when requested by an operator.
// Neither guard modifies networking, collector connectivity, proxy settings or
// the agent's authorized ability to communicate with external systems.
func runtimeIsolationFlag(name string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "", "0", "false", "off", "no":
		return false, nil
	case "1", "true", "on", "yes":
		return true, nil
	default:
		return false, fmt.Errorf("%s must be a boolean (1/0, true/false, on/off)", name)
	}
}

// ValidateRuntimeIsolation is called after ResolveExecPrivilege, before any
// stores, listeners, or agents are started. The explicit requirements prevent
// a production deployment from silently running the agent with the server's
// identity, or as host-root when the operator selected userns isolation.
//
// IMPORTANT: a remapped container UID 0 is not a non-root app server. The
// server remains namespace-root so it can provision separate executor UIDs.
// The user namespace stops this UID from being host UID 0.
func ValidateRuntimeIsolation(priv ExecPrivilege) error {
	requireExec, err := runtimeIsolationFlag("ARTEX_REQUIRE_EXEC_ISOLATION")
	if err != nil {
		return err
	}
	if requireExec && !priv.Enabled {
		return fmt.Errorf("ARTEX_REQUIRE_EXEC_ISOLATION=1 but the agent privilege drop is unavailable or disabled")
	}
	requireUserNS, err := runtimeIsolationFlag("ARTEX_REQUIRE_USERNS")
	if err != nil {
		return err
	}
	if !requireUserNS {
		return nil
	}
	if !priv.Enabled {
		return fmt.Errorf("ARTEX_REQUIRE_USERNS=1 requires an enabled, separate agent executor identity")
	}
	if err := checkUserNamespaceRootMapping(); err != nil {
		return fmt.Errorf("ARTEX_REQUIRE_USERNS=1: %w", err)
	}
	return nil
}

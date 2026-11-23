package server

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// nftEmergencyBackend writes only to the administrator-provisioned,
// ARTEX-exclusive IPv4 timeout set. No arbitrary commands or scripts are ever
// accepted. There is deliberately no fallback to iptables or general Bash.
//
// Deploy this runner only in the network namespace containing the firewall
// rules, preferably through a separately constrained host service. Giving
// the full ARTEX application CAP_NET_ADMIN is NOT recommended.
type nftEmergencyBackend struct{}

const (
	emergencyNFTTable = "artex_emergency"
	emergencyNFTSet   = "blocked_v4"
)

func runEmergencyNFT(ctx context.Context, args ...string) ([]byte, error) {
	if runtime.GOOS != "linux" {
		return nil, errors.New("nftables emergency containment requires Linux")
	}
	path, err := exec.LookPath("nft")
	if err != nil {
		return nil, errors.New("nft binary is unavailable")
	}
	output, err := exec.CommandContext(ctx, path, args...).CombinedOutput()
	if err != nil {
		// Command stderr might contain attacker-origin metadata or namespace
		// details; never expose it to the API or persist it in the audit log.
		return nil, errors.New("nft command failed or timed out")
	}
	return output, nil
}

func emergencyNFTElement(ip string) (string, error) {
	address, err := netip.ParseAddr(ip)
	if err != nil || !address.Is4() || !address.IsGlobalUnicast() ||
		address.IsPrivate() {
		return "", errors.New("source is not a public IPv4 host")
	}
	return address.String(), nil
}

// Check verifies that the predefined kernel timeout set exists. The operator
// must configure and review all packet-filter chains outside ARTEX.
func (nftEmergencyBackend) Check(ctx context.Context) error {
	out, err := runEmergencyNFT(ctx, "list", "set", "inet", emergencyNFTTable, emergencyNFTSet)
	if err != nil {
		return err
	}
	if !strings.Contains(string(out), "type ipv4_addr") ||
		!strings.Contains(string(out), "timeout") {
		return errors.New("preprovisioned nft set needs ipv4_addr and timeout support")
	}
	return nil
}

func (backend nftEmergencyBackend) present(ctx context.Context, ip string) bool {
	_, err := runEmergencyNFT(ctx, "get", "element", "inet", emergencyNFTTable, emergencyNFTSet, "{ "+ip+" }")
	return err == nil
}

// Apply is idempotent for entries already present in ARTEX's exclusive set.
// A kernel timeout limits risk even if ARTEX crashes after nft succeeds but
// before its SQL ledger transaction commits.
func (backend nftEmergencyBackend) Apply(ctx context.Context, ip string, ttl time.Duration) error {
	ip, err := emergencyNFTElement(ip)
	if err != nil {
		return err
	}
	if ttl <= 0 || ttl > 5*time.Minute {
		return errors.New("refusing unbounded emergency containment TTL")
	}
	if err := backend.Check(ctx); err != nil {
		return err
	}
	if backend.present(ctx, ip) {
		return nil
	}
	seconds := int(math.Ceil(ttl.Seconds()))
	_, err = runEmergencyNFT(ctx, "add", "element", "inet", emergencyNFTTable,
		emergencyNFTSet, fmt.Sprintf("{ %s timeout %ds }", ip, seconds))
	return err
}

// Revert removes one exact source IPv4 from ARTEX's exclusive set. Already
// absent members are an idempotent success only when the set exists.
func (backend nftEmergencyBackend) Revert(ctx context.Context, ip string) error {
	ip, err := emergencyNFTElement(ip)
	if err != nil {
		return err
	}
	if err := backend.Check(ctx); err != nil {
		return err
	}
	if !backend.present(ctx, ip) {
		return nil
	}
	_, err = runEmergencyNFT(ctx, "delete", "element", "inet", emergencyNFTTable,
		emergencyNFTSet, "{ "+ip+" }")
	return err
}

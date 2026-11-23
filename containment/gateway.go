// Package containment provides the narrowly privileged local nftables
// helper. It accepts only specific, validated actions over a Unix socket.
package containment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/Autumn-27/artex/defense"
)

type Runner interface {
	Check(context.Context) error
	Apply(context.Context, string, time.Duration) error
	Revert(context.Context, string) error
}

type NFTRunner struct{}

// No shell is used, no custom binary or set can be supplied by event data.
func nftCall(ctx context.Context, parts ...string) ([]byte, error) {
	if runtime.GOOS != "linux" {
		return nil, errors.New("nftables requires Linux")
	}
	path, err := exec.LookPath("nft")
	if err != nil {
		return nil, errors.New("nft unavailable")
	}
	out, err := exec.CommandContext(ctx, path, parts...).CombinedOutput()
	if err != nil {
		return nil, errors.New("nftables command rejected or timed out")
	}
	return out, nil
}

func publicIPv4(value string) (string, error) {
	address, err := netip.ParseAddr(value)
	if err != nil || !address.Is4() || !address.IsGlobalUnicast() || address.IsPrivate() {
		return "", errors.New("refusing non-public source IP")
	}
	return address.String(), nil
}

func (NFTRunner) Check(ctx context.Context) error {
	out, err := nftCall(ctx, "list", "set", "inet", "artex_emergency", "blocked_v4")
	if err != nil {
		return err
	}
	if !strings.Contains(string(out), "type ipv4_addr") ||
		!strings.Contains(string(out), "timeout") {
		return errors.New("dedicated set lacks IPv4 timeout support")
	}
	rules, err := nftCall(ctx, "list", "table", "inet", "artex_emergency")
	if err != nil {
		return err
	}
	if !strings.Contains(string(rules), "@blocked_v4") ||
		!strings.Contains(string(rules), "drop") {
		return errors.New("no enabled firewall drop rule references the exclusive timeout set")
	}
	return nil
}

func (NFTRunner) exists(ctx context.Context, ip string) bool {
	_, err := nftCall(ctx, "get", "element", "inet", "artex_emergency", "blocked_v4", "{ "+ip+" }")
	return err == nil
}

func (n NFTRunner) Apply(ctx context.Context, ip string, ttl time.Duration) error {
	canonical, err := publicIPv4(ip)
	if err != nil {
		return err
	}
	if ttl <= 0 || ttl > 5*time.Minute {
		return errors.New("refusing unbounded expiry")
	}
	if err := n.Check(ctx); err != nil {
		return err
	}
	if n.exists(ctx, canonical) {
		return nil
	}
	seconds := int((ttl + time.Second - 1) / time.Second)
	_, err = nftCall(ctx, "add", "element", "inet", "artex_emergency", "blocked_v4",
		fmt.Sprintf("{ %s timeout %ds }", canonical, seconds))
	return err
}

func (n NFTRunner) Revert(ctx context.Context, ip string) error {
	canonical, err := publicIPv4(ip)
	if err != nil {
		return err
	}
	if err := n.Check(ctx); err != nil {
		return err
	}
	if !n.exists(ctx, canonical) {
		return nil
	}
	_, err = nftCall(ctx, "delete", "element", "inet", "artex_emergency",
		"blocked_v4", "{ "+canonical+" }")
	return err
}

type applyRequest struct {
	SourceIP      string `json:"source_ip"`
	DestinationIP string `json:"destination_ip"`
	TTLSeconds    int    `json:"ttl_seconds"`
}

type revertRequest struct {
	SourceIP string `json:"source_ip"`
}

// Handler must NEVER be exposed on TCP. Unix filesystem permissions control
// access and the helper rechecks source, protected destination and TTL.
func Handler(cfg defense.EmergencyConfig, runner Runner) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second)
		defer cancel()
		if cfg.Mode != defense.EmergencyNFT || runner.Check(ctx) != nil {
			http.Error(w, "unavailable", 503)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ready":true}`)
	})
	mux.HandleFunc("POST /v1/apply", func(w http.ResponseWriter, r *http.Request) {
		if cfg.Mode != defense.EmergencyNFT {
			http.Error(w, "not configured for live mode", 403)
			return
		}
		var input applyRequest
		if !decodeBody(w, r, &input) {
			return
		}
		if !cfg.EligibleIP(input.SourceIP, input.DestinationIP) ||
			input.TTLSeconds < 1 || time.Duration(input.TTLSeconds)*time.Second > cfg.TTL {
			http.Error(w, "source, destination or timeout outside policy", 403)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 1500*time.Millisecond)
		defer cancel()
		if err := runner.Apply(ctx, input.SourceIP, time.Duration(input.TTLSeconds)*time.Second); err != nil {
			http.Error(w, "kernel enforcement rejected", 503)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /v1/revert", func(w http.ResponseWriter, r *http.Request) {
		var input revertRequest
		if !decodeBody(w, r, &input) {
			return
		}
		if _, err := publicIPv4(input.SourceIP); err != nil {
			http.Error(w, "source must be a public IPv4 host", 403)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 1500*time.Millisecond)
		defer cancel()
		if err := runner.Revert(ctx, input.SourceIP); err != nil {
			http.Error(w, "kernel reversal rejected", 503)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

func decodeBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		http.Error(w, "invalid JSON", 400)
		return false
	}
	var tail any
	if err := dec.Decode(&tail); err != io.EOF {
		http.Error(w, "trailing JSON", 400)
		return false
	}
	return true
}

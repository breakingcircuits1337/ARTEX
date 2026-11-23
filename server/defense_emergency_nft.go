package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// nftEmergencyBackend is the UNPRIVILEGED ARTEX client. Kernel access exists
// only in cmd/artex-emergency-agent, running in the firewall namespace.
// No shell or CAP_NET_ADMIN is required in the main ARTEX process.
type nftEmergencyBackend struct{}

func emergencySocket() (string, error) {
	path := os.Getenv("ARTEX_AUTO_CONTAIN_SOCKET")
	if path == "" {
		path = "/run/artex/emergency.sock"
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", errors.New("emergency socket must be an absolute normalized path")
	}
	return path, nil
}

func emergencyRPC(ctx context.Context, method, endpoint string, data any) error {
	path, err := emergencySocket()
	if err != nil {
		return err
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", path)
		},
		DisableKeepAlives: true,
		ForceAttemptHTTP2: false,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   2 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	var body io.Reader
	if data != nil {
		buf, err := json.Marshal(data)
		if err != nil {
			return err
		}
		body = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method,
		"http://artex-local-unix"+endpoint, body)
	if err != nil {
		return err
	}
	if data != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := client.Do(req)
	if err != nil {
		return errors.New("local containment helper is unavailable")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusNoContent {
		return errors.New("local helper rejected the scoped containment request")
	}
	return nil
}

func (nftEmergencyBackend) Check(ctx context.Context) error {
	return emergencyRPC(ctx, http.MethodGet, "/v1/health", nil)
}

func (nftEmergencyBackend) Apply(
	ctx context.Context, source, destination string, ttl time.Duration,
) error {
	if ttl <= 0 || ttl > 5*time.Minute {
		return errors.New("invalid bounded kernel TTL")
	}
	seconds := int((ttl + time.Second - 1) / time.Second)
	return emergencyRPC(ctx, http.MethodPost, "/v1/apply", map[string]any{
		"source_ip": source, "destination_ip": destination,
		"ttl_seconds": seconds,
	})
}

func (nftEmergencyBackend) Revert(ctx context.Context, source string) error {
	return emergencyRPC(ctx, http.MethodPost, "/v1/revert",
		map[string]any{"source_ip": source})
}

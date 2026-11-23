package containment

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/defense"
)

type fakeNft struct {
	applied, reversed int
	source            string
	ttl               time.Duration
}

func (f *fakeNft) Check(context.Context) error { return nil }
func (f *fakeNft) Apply(_ context.Context, source string, ttl time.Duration) error {
	f.applied++
	f.source = source
	f.ttl = ttl
	return nil
}
func (f *fakeNft) Revert(_ context.Context, source string) error {
	f.reversed++
	f.source = source
	return nil
}

func TestUnixHelperRequiresStrictScope(t *testing.T) {
	t.Setenv("ARTEX_MODE", "defense")
	t.Setenv("ARTEX_AUTO_CONTAIN_MODE", "nftables")
	t.Setenv("ARTEX_AUTO_CONTAIN_PROTECTED_CIDRS", "192.0.2.0/24")
	cfg, err := defense.LoadEmergencyConfig()
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeNft{}
	h := Handler(cfg, fake)
	test := func(path, input string, want int) {
		t.Helper()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", path, strings.NewReader(input))
		h.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Fatalf("%s: status %d, want %d: %s", path, rec.Code, want, rec.Body.String())
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/v1/health", nil))
	if rec.Code != 200 {
		t.Fatalf("helper preflight failed: %d", rec.Code)
	}
	test("/v1/apply", `{"source_ip":"1.1.1.1","destination_ip":"192.0.2.25","ttl_seconds":120}`, 204)
	if fake.applied != 1 || fake.source != "1.1.1.1" || fake.ttl != 120*time.Second {
		t.Fatalf("unexpected apply %+v", fake)
	}
	test("/v1/apply", `{"source_ip":"10.0.0.1","destination_ip":"192.0.2.25","ttl_seconds":120}`, 403)
	test("/v1/apply", `{"source_ip":"1.1.1.1","destination_ip":"8.8.8.8","ttl_seconds":120}`, 403)
	test("/v1/apply", `{"source_ip":"1.1.1.1","destination_ip":"192.0.2.25","ttl_seconds":999}`, 403)
	test("/v1/apply", `{"source_ip":"1.1.1.1","destination_ip":"192.0.2.25","ttl_seconds":120,"command":"rm -rf /"}`, 400)
	test("/v1/revert", `{"source_ip":"1.1.1.1"}`, 204)
	test("/v1/revert", `{"source_ip":"10.0.0.1"}`, 403)
	if fake.applied != 1 || fake.reversed != 1 {
		t.Fatalf("unexpected operations %+v", fake)
	}
}

func TestHelperNeverAdvertisesLiveModeWithoutConfig(t *testing.T) {
	h := Handler(defense.EmergencyConfig{Mode: defense.EmergencyOff}, &fakeNft{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/health", nil))
	if rec.Code != 503 {
		t.Fatalf("unarmed helper claims ready: %d", rec.Code)
	}
}

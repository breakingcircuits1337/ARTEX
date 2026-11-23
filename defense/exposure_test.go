package defense

import (
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestExposureIsMetadataOnly(t *testing.T) {
	port := 6379
	cases := []struct {
		a     *db.Asset
		level string
	}{
		{&db.Asset{ID: 1, Type: "service", Port: &port}, "review"},
		{&db.Asset{ID: 2, Type: "endpoint", URL: "http://internal.example/test"}, "review"},
		{&db.Asset{ID: 3, Type: "endpoint", URL: "https://internal.example/test"}, "informational"},
		{&db.Asset{ID: 4, Type: "app"}, "informational"},
	}
	for _, tc := range cases {
		got := AssessAsset(tc.a)
		if got.Level != tc.level {
			t.Errorf("asset %d: level=%s", tc.a.ID, got.Level)
		}
		if got.Confidence != "metadata-only" {
			t.Fatalf("incorrect evidence confidence: %+v", got)
		}
		if strings.Contains(strings.Join(got.Signals, " "), "confirmed vulnerability") {
			t.Fatal("metadata presented as verified vulnerability")
		}
	}
}

func TestExposurePrioritization(t *testing.T) {
	port := 22
	got := AssessAssets([]*db.Asset{{ID: 5, Type: "app"}, {ID: 7, Type: "service", Port: &port}, {ID: 2, Type: "endpoint", URL: "https://app.example"}, {ID: 1, Type: "endpoint", URL: "http://app.example"}})
	if len(got) != 4 || got[0].AssetID != 1 || got[1].AssetID != 7 || got[2].AssetID != 2 {
		t.Fatalf("unexpected sort order: %+v", got)
	}
}

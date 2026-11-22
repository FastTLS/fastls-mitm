package main

import (
	"context"
	"github.com/FastTLS/fastls/profile"
	generators "github.com/FastTLS/imitate"
	"testing"
)

func TestDeliveredBrowserCatalog(t *testing.T) {
	cases := map[string]string{
		"chrome/158/windows":  "chrome-158.0.8127.37",
		"edge/158/windows":    "edge-158.0.4370.33",
		"firefox/160/windows": "Firefox160.0.1",
	}
	for id, version := range cases {
		t.Run(id, func(t *testing.T) {
			result, err := generators.New().Resolve(context.Background(), profile.ResolveRequest{Selector: id})
			if err != nil {
				t.Fatal(err)
			}
			if result.Match.BaselineID != version || result.Match.ProviderVersion != "0.1.3" || result.Match.DataRevision != "browser-8ee4c22c6b779cbb" {
				t.Fatalf("stale delivered profile: %+v / %+v", result.Spec.Metadata, result.Match)
			}
		})
	}
}

func TestNewFirefoxSelectors(t *testing.T) {
	for _, version := range []string{"159", "160"} {
		if got := browserSelector("firefox" + version); got != "firefox/"+version+"/windows" {
			t.Fatalf("firefox%s resolved to %s", version, got)
		}
	}
}

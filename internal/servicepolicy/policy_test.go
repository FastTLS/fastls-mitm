package servicepolicy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	fastls "github.com/FastTLS/fastls"
)

func TestLoadDefaultAndMissingCapability(t *testing.T) {
	if _, err := Load(fastls.NewClient(), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := configure(struct{}{}, []byte("{}")); err == nil || !strings.Contains(err.Error(), "refusing to start") {
		t.Fatal("unsupported core did not fail closed", err)
	}
}

func TestLoadFileBoundsAndCoreCapability(t *testing.T) {
	if _, err := Load(fastls.NewClient(), filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("missing file accepted")
	}
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, []byte(strings.Repeat(" ", (1<<20)+1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(fastls.NewClient(), path); err == nil || !strings.Contains(err.Error(), "1 MiB") {
		t.Fatal("oversized file accepted", err)
	}
	if err := os.WriteFile(path, []byte(`{"deny_cidrs":["127.0.0.0/8"]}`), 0600); err != nil {
		t.Fatal(err)
	}
	client, err := Load(fastls.NewClient(), path)
	_, supported := any(fastls.NewClient()).(interface {
		WithAddressPolicyJSON([]byte) (fastls.Fastls, error)
	})
	if !supported {
		if err == nil || !strings.Contains(err.Error(), "refusing to start") {
			t.Fatal("old core ignored requested policy", err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	// The policy is compiled once, not reread on each request.
	if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	var reached atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Add(1); io.WriteString(w, "unexpected") }))
	defer target.Close()
	response, err := client.DoContext(context.Background(), target.URL, fastls.Options{}, "GET")
	if response.Body != nil {
		response.Body.Close()
	}
	response.Client.CloseIdleConnections()
	if err == nil || reached.Load() != 0 {
		t.Fatal("compiled policy was bypassed", err)
	}
}

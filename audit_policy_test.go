//go:build mitm_policy_e2e

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/FastTLS/fastls-mitm/internal/audit"
)

func TestAuditPolicyDenialsAndTunnelShutdown(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	sink, err := audit.Open(audit.Config{File: path, Queue: 32})
	if err != nil {
		t.Fatal(err)
	}
	proxy, endpoint := enabledPolicyProxyWithLimits(t, map[string]any{"allow_hosts": []string{"127.0.0.1"}, "allow_cidrs": []string{"127.0.0.1/32"}}, 0, NewMITMProxyOptions{Audit: sink})
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer target.Close()
	roots := x509.NewCertPool()
	roots.AddCert(proxy.caCert)
	transport := &http.Transport{Proxy: http.ProxyURL(endpoint), TLSClientConfig: &tls.Config{RootCAs: roots}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	for _, u := range []string{target.URL, strings.Replace(target.URL, "127.0.0.1", "localhost", 1) + "?LEAK_QUERY"} {
		r, err := client.Get(u)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, r.Body)
		r.Body.Close()
	}
	secure := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "secure") }))
	secure.EnableHTTP2 = true
	secure.StartTLS()
	defer secure.Close()
	resp, err := client.Get(secure.URL)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if err = proxy.Stop(); err != nil {
		t.Fatal(err)
	}
	// A policy denial is a fixed category, never its hostname or policy input.
	if err := sink.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("LEAK_")) {
		t.Fatal(string(data))
	}
	found := false
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte{'\n'}) {
		var e audit.Event
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatal(err)
		}
		if e.ErrorCode == "address_denied" && e.DownstreamStatus == 403 {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing denial: %s", data)
	}
	if stats := sink.Stats(); stats.DroppedClosed != 0 || stats.Accepted != stats.Written {
		t.Fatalf("undrained policy events: %+v", stats)
	}
}

func TestAuditPolicyTrafficLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	sink, err := audit.Open(audit.Config{File: path, Queue: 32})
	if err != nil {
		t.Fatal(err)
	}
	proxy, endpoint := enabledPolicyProxyWithLimits(t, map[string]any{"allow_hosts": []string{"127.0.0.1"}, "allow_cidrs": []string{"127.0.0.1/32"}}, 0, NewMITMProxyOptions{Audit: sink, PolicyTunnelMaxReadBytes: 1})
	target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("traffic-limited handshake reached origin") }))
	defer target.Close()
	roots := x509.NewCertPool()
	roots.AddCert(proxy.caCert)
	transport := &http.Transport{Proxy: http.ProxyURL(endpoint), TLSClientConfig: &tls.Config{RootCAs: roots}}
	defer transport.CloseIdleConnections()
	if r, err := (&http.Client{Transport: transport, Timeout: 2 * time.Second}).Get(target.URL); err == nil {
		r.Body.Close()
		t.Fatal("traffic limit accepted TLS handshake")
	}
	if err = proxy.Stop(); err != nil {
		t.Fatal(err)
	}
	if err = sink.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if !bytes.Contains(data, []byte("\"error_code\":\"traffic_limited\"")) {
		t.Fatal("missing traffic budget event", string(data))
	}
}

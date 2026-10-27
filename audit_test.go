package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/FastTLS/fastls-mitm/internal/audit"
)

func TestDefaultAuditStopDrainsActiveConnect(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	sink, err := audit.Open(audit.Config{File: path, Queue: 32})
	if err != nil {
		t.Fatal(err)
	}
	p := newTemporaryProxy(t)
	p.audit = sink
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := p.prepareServer(listener)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- p.servePrepared(server, listener) }()
	t.Cleanup(func() { p.Stop(); sink.Close(context.Background()) })
	started, released := make(chan struct{}), make(chan struct{})
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("prefix"))
		w.(http.Flusher).Flush()
		close(started)
		<-r.Context().Done()
		close(released)
	}))
	target.EnableHTTP2 = true
	target.StartTLS()
	defer target.Close()
	defer target.CloseClientConnections()
	u, _ := url.Parse("http://" + listener.Addr().String())
	roots := x509.NewCertPool()
	roots.AddCert(p.caCert)
	transport := &http.Transport{Proxy: http.ProxyURL(u), TLSClientConfig: &tls.Config{RootCAs: roots}}
	defer transport.CloseIdleConnections()
	response, err := (&http.Client{Transport: transport, Timeout: 3 * time.Second}).Get(target.URL + "?LEAK_QUERY")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	<-started
	if err = p.Stop(); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("proxy serve did not finish")
	}
	select {
	case <-released:
	case <-time.After(time.Second):
		t.Fatal("origin retained after stop")
	}
	if _, err = io.ReadAll(response.Body); err == nil {
		t.Fatal("stopped tunnel became successful EOF")
	}
	if err = sink.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if stats := sink.Stats(); stats.Accepted != 2 || stats.Written != 2 || stats.DroppedClosed != 0 {
		t.Fatalf("events outlived shutdown: %+v", stats)
	}
	data, _ := os.ReadFile(path)
	if bytes.Contains(data, []byte("LEAK_")) {
		t.Fatal(string(data))
	}
	events := map[string]audit.Event{}
	var child audit.Event
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte{'\n'}) {
		var e audit.Event
		if err = json.Unmarshal(line, &e); err != nil {
			t.Fatal(err)
		}
		events[e.RequestID] = e
		if e.Kind == "request" {
			child = e
		}
	}
	if child.ParentID == "" || events[child.ParentID].Kind != "connect" || child.ErrorCode != "cancelled" {
		t.Fatalf("completion relationship: %+v", events)
	}
}

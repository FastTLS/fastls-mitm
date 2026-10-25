package main

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	fastls "github.com/FastTLS/fastls"
	"github.com/FastTLS/ftransport"
)

func TestBrowserSelectorAndProvider(t *testing.T) {
	tests := map[string]string{
		"chrome": "chrome/160/windows", "chrome120": "chrome/120/windows",
		"edge155": "edge/155/windows", "firefox147": "firefox/147/windows",
		"safari": "safari/18.7.3/ipados", "opera": "opera/145/windows",
		"unknown": "firefox/158/windows",
	}
	for input, want := range tests {
		if got := browserSelector(input); got != want {
			t.Errorf("browserSelector(%q) = %q, want %q", input, got, want)
		}
	}
	options := fastls.Options{Headers: map[string]string{"X-Caller": "keep"}}
	if err := applyBrowserProfile(&options, "chrome160"); err != nil {
		t.Fatal(err)
	}
	if options.Profile == nil && options.Fingerprint == nil {
		t.Fatal("profile provider did not configure a protocol identity")
	}
	if options.UserAgent == "" || options.Headers["X-Caller"] != "keep" {
		t.Fatalf("profile application lost identity or caller headers: %#v", options.Headers)
	}
}

func TestHTTP2HandoffUsesStandardRequests(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 || r.Header.Get("X-Test") != "handoff" {
			t.Errorf("unexpected request: proto=%s headers=%v", r.Proto, r.Header)
		}
		_, _ = w.Write([]byte("h2-ok"))
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := tls.Dial("tcp", target.Host, &tls.Config{
		InsecureSkipVerify: true, // local test certificate
		NextProtos:         []string{"h2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	transport, err := newHTTP2Transport(conn, &ftransport.HTTP2Config{})
	if err != nil {
		conn.Close()
		t.Fatal(err)
	}
	defer transport.Close()

	request, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-Test", "handoff")
	request, err = withRequestOrder(request, []string{"X-Test"}, []string{":method", ":authority", ":scheme", ":path"})
	if err != nil {
		t.Fatal(err)
	}
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || response.ProtoMajor != 2 || strings.TrimSpace(string(body)) != "h2-ok" {
		t.Fatalf("proto=%s body=%q err=%v", response.Proto, body, err)
	}
}

func TestHTTP2ResponseIsWrittenAsValidHTTP1(t *testing.T) {
	client, proxy := net.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- new(MITMProxy).writeHTTP1Response(proxy, &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Length": []string{"2"}},
			Body:       io.NopCloser(strings.NewReader("ok")),
		})
		proxy.Close()
	}()
	data, err := io.ReadAll(client)
	client.Close()
	if err != nil {
		t.Fatal(err)
	}
	if writeErr := <-done; writeErr != nil {
		t.Fatal(writeErr)
	}
	if !strings.HasPrefix(string(data), "HTTP/1.1 200 OK\r\n") || strings.Contains(string(data), "200 200 OK") {
		t.Fatalf("invalid status line: %q", data)
	}
}

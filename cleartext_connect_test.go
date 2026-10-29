package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	fastls "github.com/FastTLS/fastls"
)

func TestCoreHTTPThroughMITM(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" || r.Header.Get("X-Mitm-Browser") != "" {
			t.Error("proxy controls reached the origin")
		}
		data, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "%s|%s", r.Method, data)
	}))
	defer target.Close()
	p := newTemporaryProxy(t)
	proxy := httptest.NewServer(p.handler())
	defer proxy.Close()
	defer p.Stop()
	client := fastls.NewClient()
	for _, method := range []string{"GET", "POST"} {
		response, err := client.Do(target.URL, fastls.Options{Proxy: proxy.URL, Body: "payload", Timeout: 3}, method)
		if err != nil {
			t.Fatalf("%s through MITM: %v", method, err)
		}
		data, err := io.ReadAll(response.Body)
		response.Body.Close()
		response.Client.CloseIdleConnections()
		if err != nil || string(data) != method+"|payload" {
			t.Fatalf("response %q: %v", data, err)
		}
	}
}

func TestCleartextCONNECTBindsAuthorityAndPreservesReadAhead(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "bound") }))
	defer target.Close()
	u, _ := url.Parse(target.URL)
	p := newTemporaryProxy(t)
	proxy := httptest.NewServer(p.handler())
	defer proxy.Close()
	defer p.Stop()
	endpoint, _ := url.Parse(proxy.URL)
	for _, authority := range []string{u.Host, "other.invalid:80"} {
		conn, err := net.Dial("tcp", endpoint.Host)
		if err != nil {
			t.Fatal(err)
		}
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		// Send CONNECT and the first request together to exercise buffered bytes.
		fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\nGET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", u.Host, u.Host, authority)
		reader := bufio.NewReader(conn)
		response, err := http.ReadResponse(reader, &http.Request{Method: "CONNECT"})
		if err != nil || response.StatusCode != 200 {
			conn.Close()
			t.Fatalf("CONNECT: %v", err)
		}
		response, err = http.ReadResponse(reader, &http.Request{Method: "GET"})
		if err != nil {
			conn.Close()
			t.Fatal(err)
		}
		data, _ := io.ReadAll(response.Body)
		response.Body.Close()
		conn.Close()
		if authority == u.Host {
			if response.StatusCode != 200 || string(data) != "bound" {
				t.Fatalf("response %d %q", response.StatusCode, data)
			}
		} else if response.StatusCode != 403 || strings.Contains(string(data), "bound") {
			t.Fatalf("authority escaped: %d %q", response.StatusCode, data)
		}
	}
}

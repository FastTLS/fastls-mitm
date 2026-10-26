//go:build mitm_policy_e2e

package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func assertPolicyTCPRejected(t *testing.T, endpoint *url.URL) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", endpoint.Host, time.Second)
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Second))
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", endpoint.Host)
	data := make([]byte, 1)
	n, err := conn.Read(data)
	var timeout net.Error
	if n != 0 || err == nil || errors.As(err, &timeout) && timeout.Timeout() {
		t.Fatalf("connection was queued or parsed instead of rejected: n=%d err=%v", n, err)
	}
}

func TestMITMPolicyGlobalConnectionsIncludePreheaderIdleAndHijacked(t *testing.T) {
	proxy, endpoint := enabledPolicyProxyWithLimits(t, map[string]any{"allow_hosts": []string{"127.0.0.1"}}, 0, NewMITMProxyOptions{PolicyMaxConnections: 1, PolicyMaxTunnels: 1})
	conn, err := net.DialTimeout("tcp", endpoint.Host, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	io.WriteString(conn, "GE")
	waitPolicyCondition(t, func() bool { return len(proxy.policyLimits.connections) == 1 })
	assertPolicyTCPRejected(t, endpoint)
	conn.Close()
	waitPolicyCondition(t, func() bool { return len(proxy.policyLimits.connections) == 0 })
	conn, err = net.DialTimeout("tcp", endpoint.Host, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", endpoint.Host)
	response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: "GET"})
	policyResponse(t, response, err, 200)
	if len(proxy.policyLimits.connections) != 1 {
		t.Fatal("idle keepalive connection lost its lease")
	}
	assertPolicyTCPRejected(t, endpoint)
	conn.Close()
	waitPolicyCondition(t, func() bool { return len(proxy.policyLimits.connections) == 0 })
	tunnel := policyQuotaConnect(t, endpoint, "127.0.0.1:443", 200)
	if len(proxy.policyLimits.connections) != 1 {
		t.Fatal("hijack returned global connection lease")
	}
	assertPolicyTCPRejected(t, endpoint)
	if err := proxy.Stop(); err != nil {
		t.Fatal(err)
	}
	tunnel.Close()
	waitPolicyCondition(t, func() bool { return len(proxy.policyLimits.connections) == 0 && len(proxy.policyLimits.tunnels) == 0 })
}

func TestMITMPolicyShutdownDeadlineClosesPreheaderConnections(t *testing.T) {
	proxy, endpoint := enabledPolicyProxyWithLimits(t, map[string]any{}, 0, NewMITMProxyOptions{PolicyMaxConnections: 1})
	conn, err := net.DialTimeout("tcp", endpoint.Host, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	io.WriteString(conn, "GE")
	waitPolicyCondition(t, func() bool { return len(proxy.policyLimits.connections) == 1 })
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := proxy.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("graceful deadline not reported", err)
	}
	waitPolicyCondition(t, func() bool { return len(proxy.policyLimits.connections) == 0 })
	conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("preheader connection survived forced cleanup")
	}
}

func TestMITMPolicyTrafficBudgetsIncludeHandshakeAndPipelinedBytes(t *testing.T) {
	target, connections := trackedPolicyTarget(t, true, true, func(w http.ResponseWriter, r *http.Request) { t.Error("failed handshake reached target") })
	targetURL, _ := url.Parse(target.URL)
	for _, test := range []struct {
		name        string
		read, write int64
		pipelined   bool
	}{
		{"read", 1, 0, false}, {"write", 0, 1, false}, {"pipelined-read", 1, 0, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			proxy, endpoint := enabledPolicyProxyWithLimits(t, map[string]any{"allow_hosts": []string{"127.0.0.1"}}, 0, NewMITMProxyOptions{PolicyMaxConnections: 1, PolicyMaxTunnels: 1, PolicyTunnelMaxReadBytes: test.read, PolicyTunnelMaxWriteBytes: test.write})
			var conn net.Conn
			if test.pipelined {
				raw, err := net.DialTimeout("tcp", endpoint.Host, time.Second)
				if err != nil {
					t.Fatal(err)
				}
				conn = &policyPipelinedConn{Conn: raw, reader: bufio.NewReader(raw), authority: targetURL.Host}
			} else {
				conn = policyQuotaConnect(t, endpoint, targetURL.Host, 200)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			secured := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
			if err := secured.Handshake(); err == nil {
				t.Fatal("tiny traffic quota allowed handshake")
			}
			secured.Close()
			waitPolicyCondition(t, func() bool { return len(proxy.policyLimits.connections) == 0 && len(proxy.policyLimits.tunnels) == 0 })
		})
	}
	if connections.Load() != 0 {
		t.Fatal("failed handshake opened target socket")
	}
}

type policyCountedClientConn struct {
	net.Conn
	read atomic.Int64
}

func (c *policyCountedClientConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.read.Add(int64(n))
	return n, err
}

func TestMITMPolicyCumulativeWriteBudgetCancelsLargeResponse(t *testing.T) {
	canceled := make(chan struct{})
	target, _ := trackedPolicyTarget(t, true, true, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/small" {
			w.Header().Set("Content-Length", "1024")
			io.WriteString(w, strings.Repeat("s", 1024))
			return
		}
		w.Header().Set("Content-Length", "262144")
		io.WriteString(w, strings.Repeat("x", 256<<10))
		<-r.Context().Done()
		close(canceled)
	})
	proxy, endpoint := enabledPolicyProxyWithLimits(t, map[string]any{"allow_hosts": []string{"127.0.0.1"}}, 0, NewMITMProxyOptions{PolicyMaxConnections: 1, PolicyMaxTunnels: 1, PolicyMaxInflight: 1, PolicyTunnelMaxWriteBytes: 16 << 10})
	targetURL, _ := url.Parse(target.URL)
	raw := &policyCountedClientConn{Conn: policyQuotaConnect(t, endpoint, targetURL.Host, 200)}
	secured := tls.Client(raw, &tls.Config{InsecureSkipVerify: true})
	defer secured.Close()
	if err := secured.Handshake(); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(secured)
	for i := 0; i < 2; i++ {
		fmt.Fprintf(secured, "GET /small HTTP/1.1\r\nHost: %s\r\n\r\n", targetURL.Host)
		response, err := http.ReadResponse(reader, &http.Request{Method: "GET"})
		if len(policyResponse(t, response, err, 200)) != 1024 {
			t.Fatal("small request failed")
		}
	}
	fmt.Fprintf(secured, "GET /large HTTP/1.1\r\nHost: %s\r\n\r\n", targetURL.Host)
	response, err := http.ReadResponse(reader, &http.Request{Method: "GET"})
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err == nil || len(data) >= 256<<10 {
		t.Fatal("quota truncation became a successful response", len(data), err)
	}
	if raw.read.Load() != 16<<10 {
		t.Fatalf("cumulative TLS budget was bypassed or reset per request: %d", raw.read.Load())
	}
	select {
	case <-canceled:
	case <-time.After(5 * time.Second):
		t.Fatal("traffic quota did not cancel upstream")
	}
	waitPolicyCondition(t, func() bool {
		return len(proxy.policyLimits.connections) == 0 && len(proxy.policyLimits.tunnels) == 0 && len(proxy.policyLimits.requests) == 0
	})
}

func TestMITMPolicyCumulativeReadBudgetRejectsPartialRequest(t *testing.T) {
	var calls atomic.Int32
	target, _ := trackedPolicyTarget(t, true, false, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		io.Copy(io.Discard, r.Body)
		io.WriteString(w, "ok")
	})
	proxy, endpoint := enabledPolicyProxyWithLimits(t, map[string]any{"allow_hosts": []string{"127.0.0.1"}}, 64<<10, NewMITMProxyOptions{PolicyMaxConnections: 1, PolicyMaxTunnels: 1, PolicyMaxInflight: 1, PolicyTunnelMaxReadBytes: 12 << 10})
	targetURL, _ := url.Parse(target.URL)
	secured := tls.Client(policyQuotaConnect(t, endpoint, targetURL.Host, 200), &tls.Config{InsecureSkipVerify: true})
	defer secured.Close()
	if err := secured.Handshake(); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(secured)
	for i := 0; i < 2; i++ {
		fmt.Fprintf(secured, "POST / HTTP/1.1\r\nHost: %s\r\nContent-Length: 1024\r\n\r\n%s", targetURL.Host, strings.Repeat("s", 1024))
		response, err := http.ReadResponse(reader, &http.Request{Method: "POST"})
		policyResponse(t, response, err, 200)
	}
	fmt.Fprintf(secured, "POST / HTTP/1.1\r\nHost: %s\r\nContent-Length: 32768\r\n\r\n%s", targetURL.Host, strings.Repeat("x", 32<<10))
	if response, err := http.ReadResponse(reader, &http.Request{Method: "POST"}); err == nil {
		response.Body.Close()
		t.Fatal("partial request unexpectedly completed")
	}
	waitPolicyCondition(t, func() bool {
		return len(proxy.policyLimits.connections) == 0 && len(proxy.policyLimits.tunnels) == 0 && len(proxy.policyLimits.requests) == 0
	})
	if calls.Load() != 2 {
		t.Fatal("incomplete request reached target", calls.Load())
	}
}

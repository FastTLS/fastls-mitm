//go:build mitm_policy_e2e

package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"
)

func waitPolicyCondition(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("policy resource was not released")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func policyQuotaConnect(t *testing.T, endpoint *url.URL, host string, want int) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", endpoint.Host, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", host, host)
	response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: "CONNECT"})
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != want {
		response.Body.Close()
		t.Fatalf("CONNECT status=%d want=%d", response.StatusCode, want)
	}
	if want != 200 {
		if want == 503 && response.Header.Get("X-Proxy-Error") != "overloaded" {
			t.Fatal("missing overload code")
		}
		response.Body.Close()
		conn.Close()
	}
	return conn
}

func TestMITMPolicyTunnelAdmissionAndDisconnectRelease(t *testing.T) {
	proxy, endpoint := enabledPolicyProxyWithLimits(t, map[string]any{"allow_hosts": []string{"127.0.0.1"}}, 0, NewMITMProxyOptions{PolicyMaxTunnels: 1})
	first := policyQuotaConnect(t, endpoint, "127.0.0.1:443", 200)
	policyQuotaConnect(t, endpoint, "127.0.0.1:443", 503)
	// Health is available even when the only tunnel is occupied.
	response, err := http.Get(endpoint.String() + "/")
	policyResponse(t, response, err, 200)
	first.Close()
	waitPolicyCondition(t, func() bool { return len(proxy.policyLimits.tunnels) == 0 })
	// A denial after reservation must return its permit before the next CONNECT.
	policyQuotaConnect(t, endpoint, "localhost:443", 403)
	waitPolicyCondition(t, func() bool { return len(proxy.policyLimits.tunnels) == 0 })
	second := policyQuotaConnect(t, endpoint, "127.0.0.1:443", 200)
	second.Close()
	waitPolicyCondition(t, func() bool { return len(proxy.policyLimits.tunnels) == 0 })
}

func TestMITMPolicyInflightSharedByPlainAndDecryptedRequests(t *testing.T) {
	entered, canceled := make(chan struct{}), make(chan struct{})
	target, connections := trackedPolicyTarget(t, false, false, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hold" {
			close(entered)
			<-r.Context().Done()
			close(canceled)
			return
		}
		io.WriteString(w, "ok")
	})
	secure, secureConnections := trackedPolicyTarget(t, true, true, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") })
	proxy, endpoint := enabledPolicyProxyWithLimits(t, map[string]any{"allow_hosts": []string{"127.0.0.1"}}, 0, NewMITMProxyOptions{PolicyMaxInflight: 1})
	transport := &http.Transport{Proxy: http.ProxyURL(endpoint)}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	request, _ := http.NewRequestWithContext(ctx, "GET", target.URL+"/hold", nil)
	done := make(chan error, 1)
	go func() {
		response, err := client.Do(request)
		if response != nil {
			response.Body.Close()
		}
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream not entered")
	}
	response, err := client.Get(target.URL)
	policyResponse(t, response, err, 503)
	secureURL, _ := url.Parse(secure.URL)
	conn := policyQuotaConnect(t, endpoint, secureURL.Host, 200)
	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(tlsConn, "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", secureURL.Host)
	response, err = http.ReadResponse(bufio.NewReader(tlsConn), &http.Request{Method: "GET"})
	policyResponse(t, response, err, 503)
	tlsConn.Close()
	if connections.Load() != 1 || secureConnections.Load() != 0 {
		t.Fatal("overload reached upstream")
	}
	cancel()
	select {
	case <-canceled:
	case <-time.After(5 * time.Second):
		t.Fatal("cancel did not reach target")
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("client stuck")
	}
	waitPolicyCondition(t, func() bool { return len(proxy.policyLimits.requests) == 0 })
	response, err = client.Get(target.URL)
	policyResponse(t, response, err, 200)
}

func TestMITMPolicyTunnelAgeCancelsUpstreamAndReleasesSlots(t *testing.T) {
	testMITMPolicyTunnelCancellation(t, false)
}

func TestMITMPolicyShutdownReleasesActiveQuotaSlots(t *testing.T) {
	testMITMPolicyTunnelCancellation(t, true)
}

func testMITMPolicyTunnelCancellation(t *testing.T, shutdown bool) {
	t.Helper()
	entered, canceled := make(chan struct{}), make(chan struct{})
	target, _ := trackedPolicyTarget(t, true, true, func(w http.ResponseWriter, r *http.Request) { close(entered); <-r.Context().Done(); close(canceled) })
	maximumAge := time.Second
	if shutdown {
		maximumAge = 0
	}
	proxy, endpoint := enabledPolicyProxyWithLimits(t, map[string]any{"allow_hosts": []string{"127.0.0.1"}}, 0, NewMITMProxyOptions{PolicyMaxInflight: 1, PolicyMaxTunnels: 1, PolicyTunnelMaxAge: maximumAge})
	targetURL, _ := url.Parse(target.URL)
	conn := policyQuotaConnect(t, endpoint, targetURL.Host, 200)
	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(tlsConn, "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", targetURL.Host)
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream not entered")
	}
	if shutdown {
		proxy.Stop()
	}
	_, err := http.ReadResponse(bufio.NewReader(tlsConn), &http.Request{Method: "GET"})
	if err == nil {
		t.Fatal("expired tunnel unexpectedly completed response")
	}
	select {
	case <-canceled:
	case <-time.After(5 * time.Second):
		t.Fatal("expiry did not cancel active upstream")
	}
	waitPolicyCondition(t, func() bool { return len(proxy.policyLimits.requests) == 0 && len(proxy.policyLimits.tunnels) == 0 })
	if shutdown {
		return
	}
	second := policyQuotaConnect(t, endpoint, targetURL.Host, 200)
	second.Close()
	waitPolicyCondition(t, func() bool { return len(proxy.policyLimits.tunnels) == 0 })
}

func TestMITMPolicyTunnelAgeClosesStalledHandshake(t *testing.T) {
	proxy, endpoint := enabledPolicyProxyWithLimits(t, map[string]any{"allow_hosts": []string{"127.0.0.1"}}, 0, NewMITMProxyOptions{PolicyMaxTunnels: 1, PolicyTunnelMaxAge: 100 * time.Millisecond})
	conn := policyQuotaConnect(t, endpoint, "127.0.0.1:443", 200)
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("expired stalled handshake remained open")
	}
	waitPolicyCondition(t, func() bool { return len(proxy.policyLimits.tunnels) == 0 })
}

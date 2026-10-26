//go:build mitm_policy_e2e

package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"testing"
	"time"
)

func assertMITMPolicyCLIConnectionFlags(t *testing.T, binary, directory, path string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	command := exec.CommandContext(ctx, binary, "-addr", address, "-address-policy", path, "-policy-max-connections", "1", "-policy-max-tunnels", "1", "-policy-max-inflight", "1", "-policy-tunnel-max-age", "5s", "-policy-tunnel-max-read-bytes", "1", "-policy-tunnel-max-write-bytes", "1048576")
	command.Dir = directory
	if err := command.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); command.Wait() })
	endpoint, _ := url.Parse("http://" + address)
	transport := &http.Transport{DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	health := func() {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			response, err := client.Get(endpoint.String() + "/")
			if err == nil {
				io.Copy(io.Discard, response.Body)
				response.Body.Close()
				if response.StatusCode == 200 {
					return
				}
			}
			if time.Now().After(deadline) {
				t.Fatal("CLI health did not recover", err)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	health()
	// Health used Connection: close; give the server a bounded chance to finish
	// that handler before reserving its only connection for CONNECT.
	var conn net.Conn
	for deadline := time.Now().Add(5 * time.Second); ; {
		candidate, err := net.DialTimeout("tcp", address, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		// With no HTTP bytes sent, a surviving connection can hold the lease;
		// excess connections instead close immediately. Retry if health cleanup
		// still held the previous lease.
		time.Sleep(10 * time.Millisecond)
		candidate.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
		_, err = candidate.Read(make([]byte, 1))
		if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
			candidate.SetDeadline(time.Now().Add(5 * time.Second))
			conn = candidate
			break
		}
		candidate.Close()
		if time.Now().After(deadline) {
			t.Fatal("CLI never admitted connection")
		}
	}
	defer conn.Close()
	assertPolicyTCPRejected(t, endpoint)
	// The actual command-line byte limit must make TLS fail, rather than only
	// being accepted syntactically by the flag parser.
	combined := &policyPipelinedConn{Conn: conn, authority: "127.0.0.1:443"}
	combined.reader = bufio.NewReader(conn)
	secured := tls.Client(combined, &tls.Config{InsecureSkipVerify: true})
	if err := secured.Handshake(); err == nil {
		t.Fatal("CLI ignored tunnel traffic budget")
	}
	secured.Close()
	health()
}

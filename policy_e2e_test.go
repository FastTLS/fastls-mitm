//go:build mitm_policy_e2e

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	fastls "github.com/FastTLS/fastls"
)

func enabledPolicyProxy(t *testing.T, config any, maximum int64, delegates ...Delegate) (*MITMProxy, *url.URL) {
	t.Helper()
	return enabledPolicyProxyWithLimits(t, config, maximum, NewMITMProxyOptions{}, delegates...)
}

func enabledPolicyProxyWithLimits(t *testing.T, config any, maximum int64, limits NewMITMProxyOptions, delegates ...Delegate) (*MITMProxy, *url.URL) {
	t.Helper()
	if workspace := os.Getenv("GOWORK"); !filepath.IsAbs(workspace) {
		t.Fatal("mitm_policy_e2e requires explicit absolute GOWORK")
	}
	if _, ok := any(fastls.NewClient()).(mitmAddressPolicy); !ok {
		t.Fatal("core preflight/origin capability is required; do not skip enabled tests")
	}
	directory := t.TempDir()
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "policy.json")
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	proxy, err := NewMITMProxyWithOptions(NewMITMProxyOptions{AddressPolicyFile: path, PolicyMaxRequestBytes: maximum, PolicyMaxInflight: limits.PolicyMaxInflight, PolicyMaxTunnels: limits.PolicyMaxTunnels, PolicyTunnelMaxAge: limits.PolicyTunnelMaxAge, PolicyMaxConnections: limits.PolicyMaxConnections, PolicyTunnelMaxReadBytes: limits.PolicyTunnelMaxReadBytes, PolicyTunnelMaxWriteBytes: limits.PolicyTunnelMaxWriteBytes, Browser: "firefox", CACertPath: filepath.Join(directory, "ca.pem"), CAKeyPath: filepath.Join(directory, "key.pem")})
	if err != nil {
		t.Fatal(err)
	}
	if len(delegates) > 0 {
		proxy.delegate = delegates[0]
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- proxy.serve(listener) }()
	t.Cleanup(func() {
		proxy.Stop()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("policy proxy did not stop")
		}
	})
	endpoint, _ := url.Parse("http://" + listener.Addr().String())
	for deadline := time.Now().Add(3 * time.Second); ; {
		request, _ := http.NewRequest("GET", endpoint.String()+"/", nil)
		request.Close = true
		response, err := http.DefaultClient.Do(request)
		if err == nil {
			response.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if limits.PolicyMaxConnections > 0 {
		waitPolicyCondition(t, func() bool { return len(proxy.policyLimits.connections) == 0 })
	}
	// No request may relax the snapshot by changing the file after startup.
	if err = os.WriteFile(path, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	return proxy, endpoint
}

func trackedPolicyTarget(t *testing.T, secure, h2 bool, handler http.HandlerFunc) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	connections := &atomic.Int32{}
	server := httptest.NewUnstartedServer(handler)
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	server.EnableHTTP2 = h2
	if secure {
		server.StartTLS()
	} else {
		server.Start()
	}
	t.Cleanup(server.Close)
	return server, connections
}

func policyResponse(t *testing.T, response *http.Response, err error, status int) []byte {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != status {
		t.Fatalf("status=%d body=%q err=%v", response.StatusCode, data, err)
	}
	return data
}

func TestMITMPolicyPlainBodyHeadersTrailersLimitsAndDenials(t *testing.T) {
	binary := []byte{0, 255, 128, 1}
	var requests atomic.Int32
	target, connections := trackedPolicyTarget(t, false, false, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "http://localhost:1/forbidden", 302)
			return
		}
		data, _ := io.ReadAll(r.Body)
		if !bytes.Equal(data, binary) || len(r.Header.Values("X-Repeat")) != 2 || r.Trailer.Get("X-End") != "complete" {
			t.Errorf("request body/header/trailer changed: %v %v %v", data, r.Header, r.Trailer)
		}
		if r.Header.Get("X-Private") != "" || r.Header.Get("X-Mitm-Browser") != "" || r.Header.Get("Proxy-Authorization") != "" {
			t.Error("hop/control header leak")
		}
		w.Header().Add("Set-Cookie", "a=1")
		w.Header().Add("Set-Cookie", "b=2")
		w.Header().Set("Trailer", "X-End")
		w.Write(binary)
		w.Header().Set("X-End", "complete")
	})
	_, endpoint := enabledPolicyProxy(t, map[string]any{"allow_hosts": []string{"127.0.0.1"}, "allow_cidrs": []string{"127.0.0.1/32"}}, 4)
	transport := &http.Transport{Proxy: http.ProxyURL(endpoint)}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, _ := http.NewRequest("POST", target.URL, io.NopCloser(bytes.NewReader(binary)))
	request.ContentLength = -1
	request.Trailer = http.Header{"X-End": []string{"complete"}}
	request.Header["X-Repeat"] = []string{"one", "two"}
	request.Header.Set("Connection", "X-Private")
	request.Header.Set("X-Private", "secret")
	request.Header.Set("X-Mitm-Browser", "firefox")
	request.Header.Set("Proxy-Authorization", "secret")
	response, err := client.Do(request)
	if got := policyResponse(t, response, err, 200); !bytes.Equal(got, binary) {
		t.Fatal(got)
	}
	if len(response.Header.Values("Set-Cookie")) != 2 || response.Trailer.Get("X-End") != "complete" {
		t.Fatal("response contract lost", response.Header, response.Trailer)
	}
	before := connections.Load()
	for _, chunked := range []bool{false, true} {
		request, _ := http.NewRequest("POST", target.URL, strings.NewReader("12345"))
		if chunked {
			request.Body = io.NopCloser(strings.NewReader("12345"))
			request.ContentLength = -1
		}
		response, err := client.Do(request)
		policyResponse(t, response, err, 413)
		if response.Header.Get("X-Proxy-Error") != "request_too_large" {
			t.Fatal(response.Header)
		}
	}
	for _, headers := range []http.Header{{"X-Mitm-Proxy": []string{"http://user:p03-mitm-secret@127.0.0.1:1"}}, {"Upgrade": []string{"websocket"}, "Connection": []string{"Upgrade"}}} {
		request, _ := http.NewRequest("GET", target.URL, nil)
		request.Header = headers
		response, err := client.Do(request)
		data := policyResponse(t, response, err, 403)
		if response.Header.Get("X-Proxy-Error") != "address_denied" || bytes.Contains(data, []byte("p03-mitm-secret")) {
			t.Fatal(response.Header, string(data))
		}
	}
	if connections.Load() != before || requests.Load() != 1 {
		t.Fatal("denied request opened an upstream connection", connections.Load(), requests.Load())
	}
	response, err = client.Get(target.URL + "/redirect")
	policyResponse(t, response, err, 302)
	response, err = client.Get("http://localhost:1/?token=p03-mitm-secret")
	data := policyResponse(t, response, err, 403)
	if bytes.Contains(data, []byte("p03-mitm-secret")) {
		t.Fatal("denial leaked query")
	}
}

func openPolicyCONNECT(t *testing.T, endpoint *url.URL, authority string, headers http.Header) (net.Conn, *bufio.Reader, *http.Response) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", endpoint.Host, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(4 * time.Second))
	var buffer strings.Builder
	fmt.Fprintf(&buffer, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", authority, authority)
	for name, values := range headers {
		for _, value := range values {
			fmt.Fprintf(&buffer, "%s: %s\r\n", name, value)
		}
	}
	buffer.WriteString("\r\n")
	if _, err = io.WriteString(conn, buffer.String()); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		conn.Close()
		t.Fatal(err)
	}
	return conn, reader, response
}

func policyTLS(t *testing.T, proxy *MITMProxy, conn net.Conn, serverName string) *tls.Conn {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(proxy.caCert)
	secured := tls.Client(conn, &tls.Config{RootCAs: roots, ServerName: serverName, NextProtos: []string{"http/1.1"}})
	if err := secured.Handshake(); err != nil {
		t.Fatal(err)
	}
	return secured
}

func TestMITMPolicyCONNECTChecksBefore200AndBeforeUpstreamDial(t *testing.T) {
	target, connections := trackedPolicyTarget(t, true, true, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, r.Proto) })
	u, _ := url.Parse(target.URL)
	proxy, endpoint := enabledPolicyProxy(t, map[string]any{"allow_hosts": []string{"127.0.0.1"}, "allow_cidrs": []string{"127.0.0.1/32"}}, 0)
	for _, authority := range []string{"localhost:" + u.Port(), "user:p03-mitm-secret@" + u.Host} {
		conn, _, response := openPolicyCONNECT(t, endpoint, authority, nil)
		status := 403
		// net/http rejects malformed authority/userinfo before invoking a handler.
		if strings.Contains(authority, "@") {
			status = 400
		}
		data := policyResponse(t, response, nil, status)
		conn.Close()
		if bytes.Contains(data, []byte("p03-mitm-secret")) {
			t.Fatal("CONNECT leaked credentials")
		}
	}
	conn, _, response := openPolicyCONNECT(t, endpoint, u.Host, http.Header{"X-Mitm-Proxy": []string{"http://127.0.0.1:1"}})
	policyResponse(t, response, nil, 403)
	conn.Close()
	if connections.Load() != 0 {
		t.Fatal("rejected CONNECT dialed upstream")
	}
	conn, _, response = openPolicyCONNECT(t, endpoint, u.Host, nil)
	defer conn.Close()
	if response.StatusCode != 200 {
		t.Fatal(response.StatusCode)
	}
	if connections.Load() != 0 {
		t.Fatal("CONNECT preflight created upstream socket")
	}
	tlsConn := policyTLS(t, proxy, conn, u.Hostname())
	if connections.Load() != 0 {
		t.Fatal("client handshake dialed upstream")
	}
	reader := bufio.NewReader(tlsConn)
	for i := 0; i < 2; i++ {
		fmt.Fprintf(tlsConn, "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", u.Host)
		response, err := http.ReadResponse(reader, &http.Request{Method: "GET"})
		if data := policyResponse(t, response, err, 200); string(data) != "HTTP/2.0" {
			t.Fatal(string(data))
		}
	}
	if connections.Load() != 2 {
		t.Fatal("expected separate core-controlled upstream requests", connections.Load())
	}
}

func TestMITMPolicyTunnelOriginSNINestedCONNECTAndUpgradeAreBound(t *testing.T) {
	target, connections := trackedPolicyTarget(t, true, false, func(w http.ResponseWriter, r *http.Request) { t.Error("forbidden inner request reached upstream") })
	u, _ := url.Parse(target.URL)
	proxy, endpoint := enabledPolicyProxy(t, map[string]any{"allow_cidrs": []string{"127.0.0.0/8", "::1/128"}}, 0)
	for _, wire := range []string{
		"GET / HTTP/1.1\r\nHost: localhost:" + u.Port() + "\r\n\r\n",
		"GET https://localhost:" + u.Port() + "/ HTTP/1.1\r\nHost: localhost:" + u.Port() + "\r\n\r\n",
		"CONNECT " + u.Host + " HTTP/1.1\r\nHost: " + u.Host + "\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: " + u.Host + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: " + u.Host + "\r\nX-Mitm-Proxy: http://127.0.0.1:1\r\n\r\n",
	} {
		conn, _, response := openPolicyCONNECT(t, endpoint, u.Host, nil)
		if response.StatusCode != 200 {
			t.Fatal(response.StatusCode)
		}
		secured := policyTLS(t, proxy, conn, u.Hostname())
		io.WriteString(secured, wire)
		response, err := http.ReadResponse(bufio.NewReader(secured), &http.Request{Method: "GET"})
		policyResponse(t, response, err, 403)
		secured.Close()
	}
	conn, _, _ := openPolicyCONNECT(t, endpoint, u.Host, nil)
	// Isolate SNI binding from certificate-name verification in this test.
	secured := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"})
	if err := secured.Handshake(); err == nil {
		t.Fatal("mismatched SNI accepted")
	}
	conn.Close()
	if connections.Load() != 0 {
		t.Fatal("tunnel escape dialed an upstream socket", connections.Load())
	}
}

func TestMITMPolicyCIDRDenyStopsCONNECTBefore200(t *testing.T) {
	target, connections := trackedPolicyTarget(t, true, false, func(w http.ResponseWriter, r *http.Request) { t.Error("denied CIDR reached target") })
	u, _ := url.Parse(target.URL)
	_, endpoint := enabledPolicyProxy(t, map[string]any{"deny_cidrs": []string{"127.0.0.0/8", "::1/128"}}, 0)
	for _, authority := range []string{u.Host, "localhost:" + u.Port()} {
		conn, _, response := openPolicyCONNECT(t, endpoint, authority, nil)
		policyResponse(t, response, nil, 403)
		conn.Close()
		if response.Header.Get("X-Proxy-Error-Reason") != "cidr_denied" {
			t.Fatal(response.Header)
		}
	}
	if connections.Load() != 0 {
		t.Fatal(connections.Load())
	}
}

func TestMITMPolicyBinaryCapabilityAndCAIsolation(t *testing.T) {
	for _, workspace := range []string{"off", os.Getenv("GOWORK")} {
		t.Run(workspace, func(t *testing.T) {
			name := "policy-mitm"
			if runtime.GOOS == "windows" {
				name += ".exe"
			}
			binary := filepath.Join(t.TempDir(), name)
			command := exec.Command("go", "build", "-trimpath", "-o", binary, ".")
			command.Env = append(os.Environ(), "GOWORK="+workspace)
			if data, err := command.CombinedOutput(); err != nil {
				t.Fatalf("build %v: %s", err, data)
			}
			directory := t.TempDir()
			path := filepath.Join(directory, "policy.json")
			data := []byte(`{}`)
			if workspace != "off" {
				data = []byte(`{"allow_hosts":null}`)
			}
			os.WriteFile(path, data, 0600)
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			command = exec.CommandContext(ctx, binary, "-addr", "127.0.0.1:0", "-address-policy", path)
			command.Dir = directory
			output, err := command.CombinedOutput()
			if ctx.Err() != nil || err == nil {
				t.Fatalf("unsafe startup %v %s", err, output)
			}
			if workspace == "off" && !bytes.Contains(output, []byte("refusing to start")) {
				t.Fatal(string(output))
			}
			if _, err := os.Stat(filepath.Join(directory, "mitm-ca-key.pem")); !os.IsNotExist(err) {
				t.Fatal("failed startup created CA key")
			}
			for _, name := range []string{"policy-max-request-bytes", "policy-max-inflight", "policy-max-tunnels", "policy-tunnel-max-age", "policy-max-connections", "policy-tunnel-max-read-bytes", "policy-tunnel-max-write-bytes"} {
				ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
				command := exec.CommandContext(ctx, binary, "-addr", "127.0.0.1:0", "-"+name, "0")
				command.Dir = directory
				output, err := command.CombinedOutput()
				cancel()
				if err == nil || ctx.Err() == context.DeadlineExceeded || !bytes.Contains(output, []byte("require address-policy")) {
					t.Fatalf("inactive quota flag was ignored: %s %v %s", name, err, output)
				}
			}
			if _, err := os.Stat(filepath.Join(directory, "mitm-ca-key.pem")); !os.IsNotExist(err) {
				t.Fatal("invalid resource flags created CA key")
			}
			if workspace != "off" {
				if err := os.WriteFile(path, []byte(`{}`), 0600); err != nil {
					t.Fatal(err)
				}
				t.Run("positive-connection-and-traffic-flags", func(t *testing.T) { assertMITMPolicyCLIConnectionFlags(t, binary, directory, path) })
			}
		})
	}
}

// Send CONNECT and ClientHello in one write, before waiting for the 200.
// This exercises bytes already buffered in the old HTTP server's reader.
type policyPipelinedConn struct {
	net.Conn
	reader              *bufio.Reader
	authority           string
	writeOnce, readOnce sync.Once
	readErr             error
}

func (c *policyPipelinedConn) Write(data []byte) (int, error) {
	first := false
	c.writeOnce.Do(func() { first = true })
	if first {
		header := []byte(fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", c.authority, c.authority))
		all := append(header, data...)
		n, err := c.Conn.Write(all)
		return max(0, n-len(header)), err
	}
	return c.Conn.Write(data)
}
func (c *policyPipelinedConn) Read(data []byte) (int, error) {
	c.readOnce.Do(func() {
		response, err := http.ReadResponse(c.reader, &http.Request{Method: http.MethodConnect})
		if err != nil {
			c.readErr = err
			return
		}
		if response.StatusCode != 200 {
			c.readErr = fmt.Errorf("CONNECT returned %d", response.StatusCode)
		}
	})
	if c.readErr != nil {
		return 0, c.readErr
	}
	return c.reader.Read(data)
}

func TestMITMPolicyPreservesPipelinedClientHello(t *testing.T) {
	target, _ := trackedPolicyTarget(t, true, false, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") })
	u, _ := url.Parse(target.URL)
	proxy, endpoint := enabledPolicyProxy(t, map[string]any{"allow_cidrs": []string{"127.0.0.1/32"}}, 0)
	raw, err := net.DialTimeout("tcp", endpoint.Host, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(4 * time.Second))
	combined := &policyPipelinedConn{Conn: raw, reader: bufio.NewReader(raw), authority: u.Host}
	secured := policyTLS(t, proxy, combined, u.Hostname())
	fmt.Fprintf(secured, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", u.Host)
	response, err := http.ReadResponse(bufio.NewReader(secured), &http.Request{Method: "GET"})
	if body := policyResponse(t, response, err, 200); string(body) != "ok" {
		t.Fatal(string(body))
	}
}

func TestMITMPolicyShutdownCancelsActiveUpstreamRequest(t *testing.T) {
	started, stopped := make(chan struct{}), make(chan struct{})
	target, _ := trackedPolicyTarget(t, true, true, func(w http.ResponseWriter, r *http.Request) { close(started); <-r.Context().Done(); close(stopped) })
	u, _ := url.Parse(target.URL)
	proxy, endpoint := enabledPolicyProxy(t, map[string]any{"allow_cidrs": []string{"127.0.0.1/32"}}, 0)
	conn, _, response := openPolicyCONNECT(t, endpoint, u.Host, nil)
	defer conn.Close()
	if response.StatusCode != 200 {
		t.Fatal(response.StatusCode)
	}
	secured := policyTLS(t, proxy, conn, u.Hostname())
	fmt.Fprintf(secured, "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", u.Host)
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream request did not start")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := proxy.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown left the upstream request active")
	}
}

type policyParentDelegate struct {
	DefaultDelegate
	parent  *url.URL
	failure bool
}

func (d *policyParentDelegate) ParentProxy(*http.Request) (*url.URL, error) {
	if d.failure {
		return nil, fmt.Errorf("secret in parent selection error")
	}
	return d.parent, nil
}

func TestMITMPolicyParentDelegateCannotFallBackToDirect(t *testing.T) {
	target, connections := trackedPolicyTarget(t, false, false, func(w http.ResponseWriter, r *http.Request) { t.Error("delegate bypass reached target") })
	for _, failed := range []bool{false, true} {
		parent, _ := url.Parse("http://user:p03-mitm-secret@127.0.0.1:1")
		_, endpoint := enabledPolicyProxy(t, map[string]any{"allow_cidrs": []string{"127.0.0.1/32"}}, 0, &policyParentDelegate{parent: parent, failure: failed})
		transport := &http.Transport{Proxy: http.ProxyURL(endpoint)}
		client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
		response, err := client.Get(target.URL)
		status := 403
		if failed {
			status = 502
		}
		if data := policyResponse(t, response, err, status); bytes.Contains(data, []byte("secret")) {
			t.Fatal("parent rejection leaked data")
		}
		transport.CloseIdleConnections()
	}
	if connections.Load() != 0 {
		t.Fatal("parent error fell back to direct")
	}
}

type policyAuthDelegate struct {
	DefaultDelegate
	calls atomic.Int32
}

func (d *policyAuthDelegate) Auth(ctx *Context, _ http.ResponseWriter) bool {
	d.calls.Add(1)
	return ctx.Req.Header.Get("Proxy-Authorization") == "Basic dXNlcjpwYXNz"
}

func TestMITMPolicyCONNECTAuthenticatesOnceWithoutCredentialForwarding(t *testing.T) {
	target, connections := trackedPolicyTarget(t, true, false, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" {
			t.Error("proxy credentials reached origin")
		}
		io.WriteString(w, "authenticated")
	})
	u, _ := url.Parse(target.URL)
	delegate := &policyAuthDelegate{}
	proxy, endpoint := enabledPolicyProxy(t, map[string]any{"allow_cidrs": []string{"127.0.0.1/32"}}, 0, delegate)
	conn, _, response := openPolicyCONNECT(t, endpoint, u.Host, nil)
	policyResponse(t, response, nil, 407)
	conn.Close()
	if connections.Load() != 0 {
		t.Fatal("unauthenticated CONNECT reached target")
	}
	conn, _, response = openPolicyCONNECT(t, endpoint, u.Host, http.Header{"Proxy-Authorization": []string{"Basic dXNlcjpwYXNz"}})
	defer conn.Close()
	if response.StatusCode != 200 {
		t.Fatal(response.StatusCode)
	}
	secured := policyTLS(t, proxy, conn, u.Hostname())
	fmt.Fprintf(secured, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", u.Host)
	response, err := http.ReadResponse(bufio.NewReader(secured), &http.Request{Method: "GET"})
	if data := policyResponse(t, response, err, 200); string(data) != "authenticated" {
		t.Fatal(string(data))
	}
	if delegate.calls.Load() != 2 {
		t.Fatal("origin request repeated proxy authentication", delegate.calls.Load())
	}
}

func TestMITMPolicyHTTPSBinaryTrailersAndRequestLimit(t *testing.T) {
	payload := []byte{0, 255, 128, 1}
	target, connections := trackedPolicyTarget(t, true, true, func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		if !bytes.Equal(data, payload) || r.ProtoMajor != 2 || r.Trailer.Get("X-End") != "complete" {
			t.Errorf("H2 body/trailer: %v %s %v", data, r.Proto, r.Trailer)
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Trailer", "X-Final")
		w.Header().Add("Set-Cookie", "a=1")
		w.Header().Add("Set-Cookie", "b=2")
		w.Write(payload)
		w.Header().Set("X-Final", "complete")
	})
	proxy, endpoint := enabledPolicyProxy(t, map[string]any{"allow_cidrs": []string{"127.0.0.1/32"}}, 4)
	roots := x509.NewCertPool()
	roots.AddCert(proxy.caCert)
	transport := &http.Transport{Proxy: http.ProxyURL(endpoint), TLSClientConfig: &tls.Config{RootCAs: roots}, ForceAttemptHTTP2: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 4 * time.Second}
	request, _ := http.NewRequest("POST", target.URL, io.NopCloser(bytes.NewReader(payload)))
	request.ContentLength = -1
	request.Trailer = http.Header{"X-End": []string{"complete"}}
	response, err := client.Do(request)
	if data := policyResponse(t, response, err, 200); !bytes.Equal(data, payload) {
		t.Fatal(data)
	}
	if response.ProtoMajor != 1 || response.Trailer.Get("X-Final") != "complete" || len(response.Header.Values("Set-Cookie")) != 2 {
		t.Fatal("bridged response contract lost", response)
	}
	before := connections.Load()
	request, _ = http.NewRequest("POST", target.URL, strings.NewReader("12345"))
	response, err = client.Do(request)
	policyResponse(t, response, err, 413)
	if connections.Load() != before {
		t.Fatal("oversized encrypted request reached origin")
	}
}

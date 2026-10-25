package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProxyServeAndShutdownClosesHijackedTunnels(t *testing.T) {
	proxy := newTemporaryProxy(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- proxy.serve(listener) }()

	healthURL := "http://" + listener.Addr().String() + "/"
	var response *http.Response
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		response, err = http.Get(healthURL)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("proxy did not become ready: %v", err)
	}
	response.Body.Close()

	tunnel, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fmt.Fprint(tunnel, "CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n")
	connectResponse, err := http.ReadResponse(bufio.NewReader(tunnel), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	connectResponse.Body.Close()
	if connectResponse.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d", connectResponse.StatusCode)
	}

	shutdownContext, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := proxy.Shutdown(shutdownContext); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("serve did not return after shutdown")
	}

	_ = tunnel.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := tunnel.Read(make([]byte, 1)); err == nil {
		t.Fatal("hijacked CONNECT tunnel remained open after shutdown")
	}
	tunnel.Close()
	if connection, err := net.DialTimeout("tcp", listener.Addr().String(), 200*time.Millisecond); err == nil {
		connection.Close()
		t.Fatal("listener still accepted connections after shutdown")
	}
}

func TestStartContextStopsOnCancellation(t *testing.T) {
	proxy := newTemporaryProxy(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- proxy.StartContext(ctx) }()

	started := false
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		proxy.serverMu.Lock()
		started = proxy.server != nil
		proxy.serverMu.Unlock()
		if started {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !started {
		t.Fatal("proxy did not start")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("StartContext did not return after cancellation")
	}
}

func TestCAFilesAreReloadedAndValidated(t *testing.T) {
	directory := t.TempDir()
	certPath := filepath.Join(directory, "ca-cert.pem")
	keyPath := filepath.Join(directory, "ca-key.pem")
	first, err := NewMITMProxyWithOptions(NewMITMProxyOptions{CACertPath: certPath, CAKeyPath: keyPath})
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewMITMProxyWithOptions(NewMITMProxyOptions{CACertPath: certPath, CAKeyPath: keyPath})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.caCert.Raw, second.caCert.Raw) || first.caKey.PublicKey.N.Cmp(second.caKey.PublicKey.N) != 0 {
		t.Fatal("existing CA was not reloaded")
	}

	if err := os.WriteFile(certPath, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewMITMProxyWithOptions(NewMITMProxyOptions{CACertPath: certPath, CAKeyPath: keyPath}); err == nil ||
		!strings.Contains(err.Error(), "invalid CA certificate PEM") {
		t.Fatalf("invalid CA error = %v", err)
	}
}

func TestMismatchedCAFilesAreRejected(t *testing.T) {
	firstDirectory := t.TempDir()
	firstCertPath := filepath.Join(firstDirectory, "ca-cert.pem")
	firstKeyPath := filepath.Join(firstDirectory, "ca-key.pem")
	if _, err := NewMITMProxyWithOptions(NewMITMProxyOptions{
		CACertPath: firstCertPath,
		CAKeyPath:  firstKeyPath,
	}); err != nil {
		t.Fatal(err)
	}

	secondDirectory := t.TempDir()
	secondKeyPath := filepath.Join(secondDirectory, "ca-key.pem")
	if _, err := NewMITMProxyWithOptions(NewMITMProxyOptions{
		CACertPath: filepath.Join(secondDirectory, "ca-cert.pem"),
		CAKeyPath:  secondKeyPath,
	}); err != nil {
		t.Fatal(err)
	}
	secondKey, err := os.ReadFile(secondKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(firstKeyPath, secondKey, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := NewMITMProxyWithOptions(NewMITMProxyOptions{
		CACertPath: firstCertPath,
		CAKeyPath:  firstKeyPath,
	}); err == nil || !strings.Contains(err.Error(), "do not match") {
		t.Fatalf("mismatched CA error = %v", err)
	}
}

func TestDialThroughProxyUsesBasicAuthentication(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	targetDone := make(chan error, 1)
	go func() {
		connection, err := target.Accept()
		if err != nil {
			targetDone <- err
			return
		}
		defer connection.Close()
		request := make([]byte, 4)
		if _, err := io.ReadFull(connection, request); err != nil {
			targetDone <- err
			return
		}
		if string(request) != "ping" {
			targetDone <- fmt.Errorf("target received %q", request)
			return
		}
		_, err = connection.Write([]byte("pong"))
		targetDone <- err
	}()

	authorization := make(chan string, 1)
	parent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization <- r.Header.Get("Proxy-Authorization")
		upstream, err := net.Dial("tcp", r.Host)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		client, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			upstream.Close()
			return
		}
		_, _ = fmt.Fprint(client, "HTTP/1.1 200 Connection Established\r\n\r\n")
		go func() {
			_, _ = io.Copy(upstream, client)
			upstream.Close()
		}()
		_, _ = io.Copy(client, upstream)
		client.Close()
	}))
	defer parent.Close()
	parentURL, _ := url.Parse(parent.URL)
	parentURL.User = url.UserPassword("proxy-user", "proxy-pass")

	connection, err := new(MITMProxy).dialThroughProxy(context.Background(), "tcp", target.Addr().String(), parentURL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(connection, reply); err != nil {
		t.Fatal(err)
	}
	connection.Close()
	if string(reply) != "pong" {
		t.Fatalf("proxy reply = %q", reply)
	}
	if got := <-authorization; got != "Basic cHJveHktdXNlcjpwcm94eS1wYXNz" {
		t.Fatalf("Proxy-Authorization = %q", got)
	}
	if err := <-targetDone; err != nil {
		t.Fatal(err)
	}
}

func TestDialThroughProxyPreservesBufferedTunnelData(t *testing.T) {
	parent, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	parentDone := make(chan error, 1)
	go func() {
		connection, err := parent.Accept()
		if err != nil {
			parentDone <- err
			return
		}
		defer connection.Close()
		reader := bufio.NewReader(connection)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				parentDone <- err
				return
			}
			if line == "\r\n" {
				break
			}
		}
		_, err = io.WriteString(connection, "HTTP/1.1 200 Connection Established\r\n\r\npong")
		parentDone <- err
	}()

	parentURL, _ := url.Parse("http://" + parent.Addr().String())
	connection, err := new(MITMProxy).dialThroughProxy(
		context.Background(),
		"tcp",
		"target.invalid:443",
		parentURL,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	reply := make([]byte, 4)
	if _, err := io.ReadFull(connection, reply); err != nil {
		t.Fatal(err)
	}
	if string(reply) != "pong" {
		t.Fatalf("buffered proxy data = %q", reply)
	}
	if err := <-parentDone; err != nil {
		t.Fatal(err)
	}
}

func TestDialThroughHTTPSProxyVerifiesTLSAndAuthenticates(t *testing.T) {
	target, targetDone := startEchoTarget(t)
	authorization := make(chan string, 1)
	parent := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization <- r.Header.Get("Proxy-Authorization")
		upstream, err := net.Dial("tcp", r.Host)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		client, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			upstream.Close()
			return
		}
		_, _ = fmt.Fprint(client, "HTTP/1.1 200 Connection Established\r\n\r\n")
		go func() {
			_, _ = io.Copy(upstream, client)
			upstream.Close()
		}()
		_, _ = io.Copy(client, upstream)
		client.Close()
	}))
	defer parent.Close()
	parentURL, _ := url.Parse(parent.URL)
	parentURL.User = url.UserPassword("secure-user", "secure-pass")
	if connection, err := new(MITMProxy).dialThroughProxy(context.Background(), "tcp", target, parentURL); err == nil {
		connection.Close()
		t.Fatal("HTTPS parent proxy with an untrusted certificate unexpectedly succeeded")
	}
	roots := x509.NewCertPool()
	roots.AddCert(parent.Certificate())

	connection, err := (&MITMProxy{proxyTLSRootCAs: roots}).dialThroughProxy(context.Background(), "tcp", target, parentURL)
	if err != nil {
		t.Fatal(err)
	}
	assertEchoConnection(t, connection)
	if got := <-authorization; got != "Basic c2VjdXJlLXVzZXI6c2VjdXJlLXBhc3M=" {
		t.Fatalf("Proxy-Authorization = %q", got)
	}
	if err := <-targetDone; err != nil {
		t.Fatal(err)
	}
}

func TestDialThroughSOCKS5ProxyAuthenticates(t *testing.T) {
	target, targetDone := startEchoTarget(t)
	socksAddress, socksDone := startSOCKS5Proxy(t, "socks-user", "socks-pass")
	proxyURL, _ := url.Parse("socks5://socks-user:socks-pass@" + socksAddress)

	connection, err := new(MITMProxy).dialThroughProxy(context.Background(), "tcp", target, proxyURL)
	if err != nil {
		t.Fatal(err)
	}
	assertEchoConnection(t, connection)
	if err := <-targetDone; err != nil {
		t.Fatal(err)
	}
	if err := <-socksDone; err != nil {
		t.Fatal(err)
	}
}

func TestDialThroughProxyHonorsCancellation(t *testing.T) {
	parent, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	requestReceived := make(chan net.Conn, 1)
	go func() {
		connection, err := parent.Accept()
		if err != nil {
			return
		}
		reader := bufio.NewReader(connection)
		_, _ = reader.ReadString('\n')
		requestReceived <- connection
	}()
	parentURL, _ := url.Parse("http://" + parent.Addr().String())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := new(MITMProxy).dialThroughProxy(ctx, "tcp", "127.0.0.1:443", parentURL)
		done <- err
	}()
	connection := <-requestReceived
	cancel()
	defer connection.Close()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("proxy handshake did not stop after cancellation")
	}
}

func TestDialTLSWithFingerprintHonorsCancellation(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		connection, err := target.Accept()
		if err == nil {
			accepted <- connection
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := (&MITMProxy{browser: "firefox"}).dialTLSWithFingerprint(
			ctx,
			"tcp",
			target.Addr().String(),
			"http/1.1",
			nil,
			nil,
		)
		done <- err
	}()
	var connection net.Conn
	select {
	case connection = <-accepted:
	case err := <-done:
		t.Fatalf("TLS dial ended before cancellation: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("TLS target did not accept the connection")
	}
	defer connection.Close()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("TLS cancellation error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("TLS handshake did not stop after cancellation")
	}
}

func TestProxyURLForLogRedactsCredentials(t *testing.T) {
	proxyURL, _ := url.Parse("http://private-user:private-pass@127.0.0.1:8080")
	formatted := proxyURLForLog(proxyURL)
	if strings.Contains(formatted, "private-user") || strings.Contains(formatted, "private-pass") {
		t.Fatalf("credentials leaked in %q", formatted)
	}
	if !strings.Contains(formatted, "redacted@127.0.0.1:8080") {
		t.Fatalf("unexpected redacted URL: %q", formatted)
	}
}

func TestPartialCAFilesAreRejected(t *testing.T) {
	directory := t.TempDir()
	certPath := filepath.Join(directory, "ca-cert.pem")
	keyPath := filepath.Join(directory, "ca-key.pem")
	if err := os.WriteFile(certPath, []byte("certificate placeholder"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewMITMProxyWithOptions(NewMITMProxyOptions{CACertPath: certPath, CAKeyPath: keyPath}); err == nil ||
		!strings.Contains(err.Error(), "证书存在但私钥不可用") {
		t.Fatalf("partial CA error = %v", err)
	}
}

func newTemporaryProxy(t testing.TB) *MITMProxy {
	t.Helper()
	directory := t.TempDir()
	proxy, err := NewMITMProxyWithOptions(NewMITMProxyOptions{
		ListenAddr: "127.0.0.1:0",
		CACertPath: filepath.Join(directory, "ca-cert.pem"),
		CAKeyPath:  filepath.Join(directory, "ca-key.pem"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return proxy
}

func startEchoTarget(t testing.TB) (string, <-chan error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	done := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer connection.Close()
		request := make([]byte, 4)
		if _, err := io.ReadFull(connection, request); err != nil {
			done <- err
			return
		}
		if string(request) != "ping" {
			done <- fmt.Errorf("target received %q", request)
			return
		}
		_, err = connection.Write([]byte("pong"))
		done <- err
	}()
	return listener.Addr().String(), done
}

func assertEchoConnection(t testing.TB, connection net.Conn) {
	t.Helper()
	if _, err := connection.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(connection, reply); err != nil {
		t.Fatal(err)
	}
	connection.Close()
	if string(reply) != "pong" {
		t.Fatalf("proxy reply = %q", reply)
	}
}

func startSOCKS5Proxy(t testing.TB, username, password string) (string, <-chan error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	done := make(chan error, 1)
	go func() {
		client, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer client.Close()
		reader := bufio.NewReader(client)
		greeting := make([]byte, 2)
		if _, err := io.ReadFull(reader, greeting); err != nil {
			done <- err
			return
		}
		methods := make([]byte, int(greeting[1]))
		if _, err := io.ReadFull(reader, methods); err != nil {
			done <- err
			return
		}
		if greeting[0] != 5 || !bytes.Contains(methods, []byte{2}) {
			done <- fmt.Errorf("unexpected SOCKS greeting: %v methods=%v", greeting, methods)
			return
		}
		_, _ = client.Write([]byte{5, 2})
		credentialsHeader := make([]byte, 2)
		if _, err := io.ReadFull(reader, credentialsHeader); err != nil {
			done <- err
			return
		}
		user := make([]byte, int(credentialsHeader[1]))
		if _, err := io.ReadFull(reader, user); err != nil {
			done <- err
			return
		}
		passwordLength, err := reader.ReadByte()
		if err != nil {
			done <- err
			return
		}
		providedPassword := make([]byte, int(passwordLength))
		if _, err := io.ReadFull(reader, providedPassword); err != nil {
			done <- err
			return
		}
		if credentialsHeader[0] != 1 || string(user) != username || string(providedPassword) != password {
			_, _ = client.Write([]byte{1, 1})
			done <- fmt.Errorf("unexpected SOCKS credentials")
			return
		}
		_, _ = client.Write([]byte{1, 0})

		requestHeader := make([]byte, 4)
		if _, err := io.ReadFull(reader, requestHeader); err != nil {
			done <- err
			return
		}
		if requestHeader[0] != 5 || requestHeader[1] != 1 {
			done <- fmt.Errorf("unexpected SOCKS request header: %v", requestHeader)
			return
		}
		host, err := readSOCKSHost(reader, requestHeader[3])
		if err != nil {
			done <- err
			return
		}
		portBytes := make([]byte, 2)
		if _, err := io.ReadFull(reader, portBytes); err != nil {
			done <- err
			return
		}
		port := int(portBytes[0])<<8 | int(portBytes[1])
		upstream, err := net.Dial("tcp", net.JoinHostPort(host, fmt.Sprint(port)))
		if err != nil {
			_, _ = client.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
			done <- err
			return
		}
		defer upstream.Close()
		_, _ = client.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
		copyDone := make(chan struct{}, 1)
		go func() {
			_, _ = io.Copy(upstream, reader)
			copyDone <- struct{}{}
		}()
		_, _ = io.Copy(client, upstream)
		client.Close()
		<-copyDone
		done <- nil
	}()
	return listener.Addr().String(), done
}

func readSOCKSHost(reader *bufio.Reader, addressType byte) (string, error) {
	switch addressType {
	case 1:
		address := make([]byte, 4)
		if _, err := io.ReadFull(reader, address); err != nil {
			return "", err
		}
		return net.IP(address).String(), nil
	case 3:
		length, err := reader.ReadByte()
		if err != nil {
			return "", err
		}
		address := make([]byte, int(length))
		if _, err := io.ReadFull(reader, address); err != nil {
			return "", err
		}
		return string(address), nil
	case 4:
		address := make([]byte, 16)
		if _, err := io.ReadFull(reader, address); err != nil {
			return "", err
		}
		return net.IP(address).String(), nil
	default:
		return "", fmt.Errorf("unsupported SOCKS address type %d", addressType)
	}
}

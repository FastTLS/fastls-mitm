package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestMITMProxyLocalHTTPAndHTTPS(t *testing.T) {
	temporary := t.TempDir()
	proxy, err := NewMITMProxyWithOptions(NewMITMProxyOptions{
		ListenAddr: "127.0.0.1:0",
		CACertPath: filepath.Join(temporary, "ca-cert.pem"),
		CAKeyPath:  filepath.Join(temporary, "ca-key.pem"),
	})
	if err != nil {
		t.Fatal(err)
	}
	proxyServer := httptest.NewServer(proxy.handler())
	defer proxyServer.Close()
	proxyURL, err := url.Parse(proxyServer.URL)
	if err != nil {
		t.Fatal(err)
	}

	httpTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Mitm-Browser") != "" {
			t.Error("MITM control header leaked to HTTP target")
		}
		_, _ = io.WriteString(w, "http-through-proxy")
	}))
	defer httpTarget.Close()

	httpTransport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	httpClient := &http.Client{Transport: httpTransport}
	httpRequest, _ := http.NewRequest(http.MethodGet, httpTarget.URL, nil)
	httpRequest.Header.Set("X-Mitm-Browser", "firefox158")
	httpResponse, err := httpClient.Do(httpRequest)
	if err != nil {
		t.Fatal(err)
	}
	httpBody, err := io.ReadAll(httpResponse.Body)
	httpResponse.Body.Close()
	httpTransport.CloseIdleConnections()
	if err != nil || httpResponse.StatusCode != http.StatusOK || string(httpBody) != "http-through-proxy" {
		t.Fatalf("HTTP proxy result: status=%d body=%q err=%v", httpResponse.StatusCode, httpBody, err)
	}

	httpsTarget := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Mitm-Browser") != "" {
			t.Error("MITM control header leaked to HTTPS target")
		}
		_, _ = io.WriteString(w, "https-through-mitm")
	}))
	defer httpsTarget.Close()

	roots := x509.NewCertPool()
	roots.AddCert(proxy.caCert)
	httpsTransport := &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
	}
	httpsClient := &http.Client{Transport: httpsTransport}
	httpsRequest, _ := http.NewRequest(http.MethodGet, httpsTarget.URL, nil)
	httpsRequest.Header.Set("X-Mitm-Browser", "firefox158")
	httpsResponse, err := httpsClient.Do(httpsRequest)
	if err != nil {
		t.Fatal(err)
	}
	httpsBody, err := io.ReadAll(httpsResponse.Body)
	httpsResponse.Body.Close()
	httpsTransport.CloseIdleConnections()
	if err != nil || httpsResponse.StatusCode != http.StatusOK || string(httpsBody) != "https-through-mitm" {
		t.Fatalf("HTTPS proxy result: status=%d body=%q err=%v", httpsResponse.StatusCode, httpsBody, err)
	}
	if httpsResponse.TLS == nil || len(httpsResponse.TLS.PeerCertificates) == 0 ||
		httpsResponse.TLS.PeerCertificates[0].Issuer.String() != proxy.caCert.Subject.String() {
		t.Fatal("client did not receive a certificate issued by the development MITM CA")
	}
}

func TestCONNECTAuthenticationRunsBeforeSuccess(t *testing.T) {
	delegate := &rejectingDelegate{}
	proxy := &MITMProxy{delegate: delegate, listenAddr: "127.0.0.1:0"}
	server := httptest.NewServer(proxy.handler())
	defer server.Close()
	serverURL, _ := url.Parse(server.URL)

	connection, err := net.Dial("tcp", serverURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_, _ = fmt.Fprint(connection, "CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n")
	response, err := http.ReadResponse(bufio.NewReader(connection), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("CONNECT status = %d, want 407", response.StatusCode)
	}
	if !strings.Contains(response.Header.Get("Proxy-Authenticate"), "Basic") {
		t.Fatalf("missing proxy authentication challenge: %v", response.Header)
	}
	if delegate.authCalls.Load() != 1 || delegate.finishCalls.Load() != 1 {
		t.Fatalf("delegate calls: auth=%d finish=%d", delegate.authCalls.Load(), delegate.finishCalls.Load())
	}
}

type rejectingDelegate struct {
	DefaultDelegate
	authCalls   atomic.Int64
	finishCalls atomic.Int64
}

func (d *rejectingDelegate) Auth(*Context, http.ResponseWriter) bool {
	d.authCalls.Add(1)
	return false
}

func (d *rejectingDelegate) Finish(*Context) {
	d.finishCalls.Add(1)
}

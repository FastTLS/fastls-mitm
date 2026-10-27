package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

// Exercise the default (no address policy) network paths, including the
// decrypted CONNECT parser. A recorder cannot detect a false successful EOF.
func TestDefaultProxyWireContract(t *testing.T) {
	assertDefaultProxyWireContract(t, 1, func(t *testing.T) (*url.URL, *x509.CertPool) {
		p := newTemporaryProxy(t)
		proxy := httptest.NewServer(p.handler())
		t.Cleanup(proxy.Close)
		t.Cleanup(func() { _ = p.Stop() })
		proxyURL, _ := url.Parse(proxy.URL)
		roots := x509.NewCertPool()
		roots.AddCert(p.caCert)
		return proxyURL, roots
	})
}

type shortDefaultDeadline struct{ DefaultDelegate }

func (*shortDefaultDeadline) BeforeRequest(ctx *Context) { ctx.Options.Timeout = 1 }

func TestDefaultProxyTotalDeadline(t *testing.T) {
	for _, protocol := range []string{"http", "https-h1", "https-h2", "tls-stall"} {
		for _, stage := range []string{"headers", "body"} {
			if protocol == "tls-stall" && stage == "body" {
				continue
			}
			t.Run(protocol+"/"+stage, func(t *testing.T) {
				p := newTemporaryProxy(t)
				p.delegate = &shortDefaultDeadline{}
				proxy := httptest.NewServer(p.handler())
				defer proxy.Close()
				defer p.Stop()
				proxyURL, _ := url.Parse(proxy.URL)
				roots := x509.NewCertPool()
				roots.AddCert(p.caCert)
				transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: roots}}
				defer transport.CloseIdleConnections()
				client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
				released := make(chan struct{}, 1)
				var endpoint string
				if protocol == "tls-stall" {
					listener, err := net.Listen("tcp", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					defer listener.Close()
					go func() {
						conn, err := listener.Accept()
						if err != nil {
							return
						}
						defer conn.Close()
						io.Copy(io.Discard, conn)
						released <- struct{}{}
					}()
					endpoint = "https://" + listener.Addr().String()
				} else {
					target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if stage == "body" {
							fmt.Fprint(w, "prefix")
							w.(http.Flusher).Flush()
						}
						<-r.Context().Done()
						released <- struct{}{}
					}))
					if protocol == "http" {
						target.Start()
					} else {
						target.EnableHTTP2 = protocol == "https-h2"
						target.StartTLS()
					}
					defer target.Close()
					defer target.CloseClientConnections()
					endpoint = target.URL
				}
				start := time.Now()
				resp, err := client.Get(endpoint)
				if err != nil {
					t.Fatal(err)
				}
				_, readErr := io.ReadAll(resp.Body)
				resp.Body.Close()
				if stage == "headers" && resp.StatusCode != 502 {
					t.Fatalf("status=%d", resp.StatusCode)
				}
				if stage == "body" && readErr == nil {
					t.Fatal("deadline became successful EOF")
				}
				if elapsed := time.Since(start); elapsed < 800*time.Millisecond || elapsed > 2500*time.Millisecond {
					t.Fatalf("deadline elapsed=%v", elapsed)
				}
				select {
				case <-released:
				case <-time.After(time.Second):
					t.Fatal("deadline did not release upstream")
				}
			})
		}
	}
}

func TestMITMBinaryDefaultWireContract(t *testing.T) {
	binary := buildMITMTestBinary(t)
	assertDefaultProxyWireContract(t, 1, func(t *testing.T) (*url.URL, *x509.CertPool) {
		address := reserveMITMLoopbackAddress(t)
		directory := t.TempDir()
		cert := filepath.Join(directory, "ca.pem")
		process := startMITMTestBinary(t, binary, "-addr", address, "-ca-cert", cert, "-ca-key", filepath.Join(directory, "key.pem"))
		waitForMITMHTTP(t, "http://"+address+"/", process)
		pem, err := os.ReadFile(cert)
		if err != nil {
			t.Fatal(err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			t.Fatal("invalid MITM CA")
		}
		proxyURL, _ := url.Parse("http://" + address)
		return proxyURL, roots
	})
}

func TestDefaultProxyRetiredUpstream(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(fmt.Sprintf("h2=%v", h2), func(t *testing.T) {
			p := newTemporaryProxy(t)
			proxy := httptest.NewServer(p.handler())
			defer proxy.Close()
			defer p.Stop()
			u, _ := url.Parse(proxy.URL)
			roots := x509.NewCertPool()
			roots.AddCert(p.caCert)
			transport := &http.Transport{Proxy: http.ProxyURL(u), TLSClientConfig: &tls.Config{RootCAs: roots}}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
			target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
			target.EnableHTTP2 = h2
			target.StartTLS()
			defer target.Close()
			for i := 0; i < 2; i++ {
				resp, err := client.Get(target.URL)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil || resp.StatusCode != 200 || string(body) != "ok" {
					t.Fatalf("request %d: status=%d body=%q err=%v", i, resp.StatusCode, body, err)
				}
				if i == 0 {
					target.CloseClientConnections()
				}
			}
		})
	}
}

func assertDefaultProxyWireContract(t *testing.T, expectedConnections int64, newProxy func(*testing.T) (*url.URL, *x509.CertPool)) {
	for _, protocol := range []string{"http", "https-h1", "https-h2"} {
		t.Run(protocol, func(t *testing.T) {
			proxyURL, roots := newProxy(t)
			transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: roots}}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			payload := []byte{0, 255, 128, 1, '\r', '\n'}
			var compressed bytes.Buffer
			zw := gzip.NewWriter(&compressed)
			zw.Write(payload)
			zw.Close()
			var targetConnections atomic.Int64
			started, cancelled := make(chan struct{}, 1), make(chan struct{}, 1)
			target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Origin-Protocol", r.Proto)
				switch r.URL.Path {
				case "/redirect":
					http.Redirect(w, r, "/binary", http.StatusFound)
				case "/binary":
					w.Header().Add("X-Repeat", "one")
					w.Header().Add("X-Repeat", "two")
					w.Header().Add("Set-Cookie", "a=1; Path=/")
					w.Header().Add("Set-Cookie", "b=2; Expires=Wed, 21 Oct 2037 07:28:00 GMT")
					w.Header().Set("Trailer", "X-Final")
					w.WriteHeader(200)
					w.(http.Flusher).Flush() // unknown length, even for the small body
					w.Write(payload)
					w.Header()["X-Final"] = []string{"first", "second"}
				case "/gzip":
					w.Header().Set("Content-Encoding", "gzip")
					w.Write(compressed.Bytes())
				case "/echo":
					data, err := io.ReadAll(r.Body)
					if err != nil {
						http.Error(w, "bad body", 400)
						return
					}
					w.Header()["X-Repeat"] = r.Header.Values("X-Repeat")
					w.Write(data)
				case "/head":
					w.Header().Set("Content-Length", "123")
				case "/reset":
					w.Write([]byte("prefix"))
					w.(http.Flusher).Flush()
					panic(http.ErrAbortHandler)
				case "/truncated":
					w.Header().Set("Content-Length", "100")
					w.Write([]byte("short"))
				case "/hold", "/hold-body":
					if r.URL.Path == "/hold-body" {
						w.Write([]byte("prefix"))
						w.(http.Flusher).Flush()
					}
					started <- struct{}{}
					<-r.Context().Done()
					cancelled <- struct{}{}
				}
			}))
			target.Config.ConnState = func(_ net.Conn, s http.ConnState) {
				if s == http.StateNew {
					targetConnections.Add(1)
				}
			}
			if protocol == "http" {
				target.Start()
			} else {
				target.EnableHTTP2 = protocol == "https-h2"
				target.StartTLS()
			}
			defer target.Close()
			defer target.CloseClientConnections()
			get := func(path string) *http.Response {
				t.Helper()
				req, _ := http.NewRequest("GET", target.URL+path, nil)
				req.Header.Set("Accept-Encoding", "gzip") // preserve wire bytes at both hops
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				return resp
			}
			t.Run("binary-headers-trailers-reuse", func(t *testing.T) {
				before := targetConnections.Load()
				for i := 0; i < 2; i++ {
					resp := get("/binary")
					body, err := io.ReadAll(resp.Body)
					resp.Body.Close()
					wantProto := "HTTP/1.1"
					if protocol == "https-h2" {
						wantProto = "HTTP/2.0"
					}
					if err != nil || !bytes.Equal(body, payload) || resp.ProtoMajor != 1 || resp.Header.Get("X-Origin-Protocol") != wantProto {
						t.Fatalf("body=%x proto=%s origin=%s err=%v", body, resp.Proto, resp.Header.Get("X-Origin-Protocol"), err)
					}
					if !reflect.DeepEqual(resp.Header.Values("X-Repeat"), []string{"one", "two"}) || len(resp.Header.Values("Set-Cookie")) != 2 || !reflect.DeepEqual(resp.Trailer.Values("X-Final"), []string{"first", "second"}) {
						t.Fatalf("headers=%v trailers=%v", resp.Header, resp.Trailer)
					}
				}
				if protocol != "http" && targetConnections.Load()-before != expectedConnections {
					t.Fatalf("CONNECT did not reuse upstream: connections=%d", targetConnections.Load()-before)
				}
			})
			t.Run("redirect-belongs-to-caller", func(t *testing.T) {
				resp := get("/redirect")
				defer resp.Body.Close()
				io.Copy(io.Discard, resp.Body)
				if resp.StatusCode != 302 || resp.Header.Get("Location") != "/binary" {
					t.Fatalf("status=%d location=%s", resp.StatusCode, resp.Header.Get("Location"))
				}
			})
			t.Run("gzip-wire-bytes", func(t *testing.T) {
				resp := get("/gzip")
				defer resp.Body.Close()
				body, err := io.ReadAll(resp.Body)
				if err != nil || resp.Header.Get("Content-Encoding") != "gzip" || !bytes.Equal(body, compressed.Bytes()) {
					t.Fatalf("body=%x encoding=%s err=%v", body, resp.Header.Get("Content-Encoding"), err)
				}
			})
			t.Run("streaming-post", func(t *testing.T) {
				req, _ := http.NewRequest("POST", target.URL+"/echo", io.NopCloser(bytes.NewReader(payload)))
				req.Header["X-Repeat"] = []string{"first", "second"}
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				body, err := io.ReadAll(resp.Body)
				if err != nil || !bytes.Equal(body, payload) || !reflect.DeepEqual(resp.Header.Values("X-Repeat"), []string{"first", "second"}) {
					t.Fatalf("body=%x headers=%v err=%v", body, resp.Header, err)
				}
			})
			t.Run("head-metadata", func(t *testing.T) {
				req, _ := http.NewRequest("HEAD", target.URL+"/head", nil)
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				body, err := io.ReadAll(resp.Body)
				if err != nil || len(body) != 0 || resp.ContentLength != 123 {
					t.Fatalf("HEAD body=%x length=%d err=%v", body, resp.ContentLength, err)
				}
			})
			for _, path := range []string{"/truncated", "/reset"} {
				t.Run("failure"+path, func(t *testing.T) {
					resp, err := client.Get(target.URL + path)
					if err == nil {
						_, err = io.ReadAll(resp.Body)
						resp.Body.Close()
					}
					if err == nil {
						t.Fatal("truncated upstream became successful EOF")
					}
				})
			}
			for _, path := range []string{"/hold", "/hold-body"} {
				t.Run("cancel"+path, func(t *testing.T) {
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					req, _ := http.NewRequestWithContext(ctx, "GET", target.URL+path, nil)
					done := make(chan struct{})
					go func() {
						resp, err := client.Do(req)
						if err == nil {
							io.Copy(io.Discard, resp.Body)
							resp.Body.Close()
						}
						close(done)
					}()
					select {
					case <-started:
					case <-time.After(2 * time.Second):
						t.Fatal("target never started")
					}
					cancel()
					select {
					case <-done:
					case <-time.After(2 * time.Second):
						t.Fatal("caller blocked after cancel")
					}
					select {
					case <-cancelled:
					case <-time.After(2 * time.Second):
						t.Fatal("upstream retained after caller cancel")
					}
				})
			}
		})
	}
}

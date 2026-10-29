package main

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	fastls "github.com/FastTLS/fastls"
)

func TestMITMProfileControlsClientHello(t *testing.T) {
	for _, browser := range []string{"firefox158", "chrome160"} {
		t.Run(browser, func(t *testing.T) {
			observed := make(chan *tls.ClientHelloInfo, 1)
			peer := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
			peer.TLS = &tls.Config{GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
				copy := *hello
				copy.CipherSuites = append([]uint16(nil), hello.CipherSuites...)
				observed <- &copy
				return nil, nil
			}}
			peer.StartTLS()
			defer peer.Close()
			u, _ := url.Parse(peer.URL)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			conn, err := (&MITMProxy{browser: browser}).dialTLSWithFingerprint(ctx, "tcp", u.Host, "http/1.1", nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			conn.Close()
			var hello *tls.ClientHelloInfo
			select {
			case hello = <-observed:
			case <-ctx.Done():
				t.Fatal("peer did not observe a ClientHello")
			}
			options := fastls.Options{Headers: map[string]string{}}
			if err := applyBrowserProfile(&options, browser); err != nil {
				t.Fatal(err)
			}
			expected := []uint16{}
			for _, code := range options.Profile.TLS.CipherSuites {
				expected = append(expected, uint16(code))
			}
			withoutGrease := func(values []uint16) []uint16 {
				result := []uint16{}
				for _, value := range values {
					if value&0x0f0f != 0x0a0a || byte(value) != byte(value>>8) {
						result = append(result, value)
					}
				}
				return result
			}
			if !reflect.DeepEqual(withoutGrease(hello.CipherSuites), withoutGrease(expected)) {
				t.Fatalf("observed cipher order %x, expected %x", hello.CipherSuites, expected)
			}
			if !reflect.DeepEqual(hello.SupportedProtos, []string{"http/1.1"}) {
				t.Fatal("forced ALPN did not reach the wire", hello.SupportedProtos)
			}
		})
	}
}

func TestInvalidTLSFingerprintFailsBeforeDial(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := (&MITMProxy{}).dialTLSWithFingerprint(ctx, "tcp", "invalid.invalid:443", "", &RequestFingerprintConfig{Override: true, JA3: "invalid"}, nil)
	if err == nil || !strings.Contains(err.Error(), "invalid TLS profile") {
		t.Fatalf("unexpected result: %v", err)
	}
}

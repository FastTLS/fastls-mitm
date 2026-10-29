//go:build mitm_policy_e2e

package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"testing"
)

func TestMITMPolicyCleartextCONNECTSchemeAndOrigin(t *testing.T) {
	target, connections := trackedPolicyTarget(t, false, false, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "policy-http") })
	u, _ := url.Parse(target.URL)
	for _, schemes := range [][]string{{"http"}, {"https"}, {"http", "https"}} {
		t.Run(fmt.Sprint(schemes), func(t *testing.T) {
			_, endpoint := enabledPolicyProxy(t, map[string]any{"allow_schemes": schemes, "allow_hosts": []string{"127.0.0.1"}, "allow_cidrs": []string{"127.0.0.1/32"}}, 0)
			for _, authority := range []string{u.Host, "other.invalid:80"} {
				before := connections.Load()
				conn, _, response := openPolicyCONNECT(t, endpoint, u.Host, nil)
				if response.StatusCode != 200 {
					conn.Close()
					t.Fatal(response.StatusCode)
				}
				fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", authority)
				response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: "GET"})
				if len(schemes) == 1 && schemes[0] == "https" {
					conn.Close()
					if err == nil {
						response.Body.Close()
						t.Fatal("HTTP accepted by HTTPS-only policy")
					}
				} else {
					status := 200
					if authority != u.Host {
						status = 403
					}
					data := policyResponse(t, response, err, status)
					conn.Close()
					if status == 200 && string(data) != "policy-http" {
						t.Fatal(string(data))
					}
				}
				if (authority != u.Host || len(schemes) == 1 && schemes[0] == "https") && connections.Load() != before {
					t.Fatal("denied request opened an origin connection")
				}
			}
		})
	}
}

func TestMITMPolicyTLSCannotUseHTTPOnlyPermission(t *testing.T) {
	target, connections := trackedPolicyTarget(t, true, false, func(w http.ResponseWriter, r *http.Request) { t.Error("denied TLS reached the origin") })
	u, _ := url.Parse(target.URL)
	_, endpoint := enabledPolicyProxy(t, map[string]any{"allow_schemes": []string{"http"}, "allow_cidrs": []string{"127.0.0.1/32"}}, 0)
	conn, _, response := openPolicyCONNECT(t, endpoint, u.Host, nil)
	defer conn.Close()
	if response.StatusCode != 200 {
		t.Fatal(response.StatusCode)
	}
	secured := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: u.Hostname()})
	if err := secured.Handshake(); err == nil {
		t.Fatal("TLS accepted by HTTP-only permission")
	}
	if connections.Load() != 0 {
		t.Fatal("denied TLS opened an origin connection")
	}
}

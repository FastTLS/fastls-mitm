//go:build mitm_policy_e2e

package main

import (
	"net"
	"net/http"
	"net/url"
	"testing"
)

func TestMITMPolicyUnspecifiedTargetsNeverDial(t *testing.T) {
	target, connections := trackedPolicyTarget(t, false, false, func(w http.ResponseWriter, r *http.Request) {
		t.Error("unspecified destination reached loopback target")
	})
	u, _ := url.Parse(target.URL)
	_, endpoint := enabledPolicyProxy(t, map[string]any{
		"allow_cidrs": []string{"0.0.0.0/0", "::/0"},
		"deny_cidrs":  []string{"127.0.0.0/8", "::1/128"},
	}, 0)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(endpoint)}}
	defer client.CloseIdleConnections()
	for _, host := range []string{"0.0.0.0", "::", "::ffff:0.0.0.0"} {
		authority := net.JoinHostPort(host, u.Port())
		t.Run("HTTP/"+host, func(t *testing.T) {
			response, err := client.Get("http://" + authority + "/")
			policyResponse(t, response, err, http.StatusForbidden)
			if response.Header.Get("X-Proxy-Error-Reason") != "invalid_ip" || connections.Load() != 0 {
				t.Fatal("denial must precede outbound dial", response.Header, connections.Load())
			}
		})
		t.Run("CONNECT/"+host, func(t *testing.T) {
			conn, _, response := openPolicyCONNECT(t, endpoint, authority, nil)
			defer conn.Close()
			policyResponse(t, response, nil, http.StatusForbidden)
			if response.Header.Get("X-Proxy-Error-Reason") != "invalid_ip" || connections.Load() != 0 {
				t.Fatal("denial must precede CONNECT success and outbound dial", response.Header, connections.Load())
			}
		})
	}
}

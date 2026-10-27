//go:build mitm_policy_e2e

package main

import (
	"crypto/x509"
	"net/url"
	"testing"
)

func TestPolicyProxyWireContract(t *testing.T) {
	// Policy mode deliberately closes the one-shot core client after each
	// request, so two requests use two upstream connections. The response and
	// cancellation assertions remain identical to the default-mode fixture.
	assertDefaultProxyWireContract(t, 2, func(t *testing.T) (*url.URL, *x509.CertPool) {
		p, endpoint := enabledPolicyProxy(t, map[string]any{"allow_hosts": []string{"127.0.0.1"}, "allow_cidrs": []string{"127.0.0.1/32"}}, 0)
		roots := x509.NewCertPool()
		roots.AddCert(p.caCert)
		return endpoint, roots
	})
}

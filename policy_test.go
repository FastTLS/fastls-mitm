package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	fastls "github.com/FastTLS/fastls"
)

func TestMITMPolicyStartupValidatesBeforeCA(t *testing.T) {
	directory := t.TempDir()
	policy := filepath.Join(directory, "policy.json")
	if err := os.WriteFile(policy, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(directory, "ca.pem")
	keyPath := filepath.Join(directory, "key.pem")
	proxy, err := NewMITMProxyWithOptions(NewMITMProxyOptions{AddressPolicyFile: policy, CACertPath: certPath, CAKeyPath: keyPath})
	_, supported := any(fastls.NewClient()).(mitmAddressPolicy)
	if supported {
		if err != nil || proxy.policy == nil {
			t.Fatal(err)
		}
	} else {
		if err == nil || !strings.Contains(err.Error(), "refusing to start") {
			t.Fatal("old core accepted policy", err)
		}
		if _, err := os.Stat(certPath); !os.IsNotExist(err) {
			t.Fatal("failed policy startup created CA material")
		}
	}
	for _, maximum := range []int64{-1, 1, policyDefaultRequestBytes, 65 << 20} {
		if _, _, err := loadMITMAddressPolicy("", maximum); err == nil {
			t.Fatal("invalid or inactive maximum accepted", maximum)
		}
	}
}

func TestMITMPolicyHeadersStripMixedCaseHopAndControlFields(t *testing.T) {
	input := http.Header{"connection": []string{"x-private"}, "x-private": []string{"secret"}, "proxy-authorization": []string{"secret"}, "x-mitm-proxy": []string{"secret"}, "X-Repeat": []string{"one", "two"}}
	output := policyHeaders(input)
	if len(output) != 1 || len(output["X-Repeat"]) != 2 {
		t.Fatal(output)
	}
	if len(input) != 5 {
		t.Fatal("source headers mutated")
	}
}

func FuzzMITMPolicyHeaders(f *testing.F) {
	f.Add("x-mitm-proxy", "secret")
	f.Add("connection", "X-Private")
	f.Add("X-Repeat", "one")
	f.Fuzz(func(t *testing.T, name, value string) {
		if len(name) > 2048 || len(value) > 8192 {
			t.Skip()
		}
		input := http.Header{name: []string{value}, "connection": []string{"x-private"}, "x-private": []string{"secret"}}
		for key := range policyHeaders(input) {
			lower := strings.ToLower(key)
			if strings.HasPrefix(lower, "x-mitm-") || lower == "connection" || lower == "x-private" || lower == "proxy-authorization" {
				t.Fatal("hop/control leak", key)
			}
		}
	})
}

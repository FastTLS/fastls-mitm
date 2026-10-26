package main

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"
)

// policyLimits is immutable after startup. Channels reserve admission before
// body buffering / DNS / certificate preparation, without an unbounded queue.
type policyLimits struct {
	connections         chan struct{}
	requests            chan struct{}
	tunnels             chan struct{}
	tunnelMaxAge        time.Duration
	tunnelMaxReadBytes  int64
	tunnelMaxWriteBytes int64
}

func newPolicyLimits(opts NewMITMProxyOptions) (policyLimits, error) {
	if opts.PolicyMaxConnections < 0 || opts.PolicyMaxConnections > 65536 {
		return policyLimits{}, errors.New("policy-max-connections must be 0..65536")
	}
	if opts.PolicyTunnelMaxReadBytes < 0 || opts.PolicyTunnelMaxReadBytes > 1<<40 {
		return policyLimits{}, errors.New("policy-tunnel-max-read-bytes must be 0..1099511627776")
	}
	if opts.PolicyTunnelMaxWriteBytes < 0 || opts.PolicyTunnelMaxWriteBytes > 1<<40 {
		return policyLimits{}, errors.New("policy-tunnel-max-write-bytes must be 0..1099511627776")
	}
	if opts.PolicyMaxInflight < 0 || opts.PolicyMaxInflight > 65536 {
		return policyLimits{}, errors.New("policy-max-inflight must be 0..65536")
	}
	if opts.PolicyMaxTunnels < 0 || opts.PolicyMaxTunnels > 65536 {
		return policyLimits{}, errors.New("policy-max-tunnels must be 0..65536")
	}
	if opts.PolicyTunnelMaxAge < 0 || opts.PolicyTunnelMaxAge > 24*time.Hour {
		return policyLimits{}, errors.New("policy-tunnel-max-age must be 0..24h")
	}
	if opts.AddressPolicyFile == "" && (opts.PolicyMaxConnections != 0 || opts.PolicyMaxInflight != 0 || opts.PolicyMaxTunnels != 0 || opts.PolicyTunnelMaxAge != 0 || opts.PolicyTunnelMaxReadBytes != 0 || opts.PolicyTunnelMaxWriteBytes != 0) {
		return policyLimits{}, errors.New("policy resource limits require address-policy")
	}
	limits := policyLimits{tunnelMaxAge: opts.PolicyTunnelMaxAge, tunnelMaxReadBytes: opts.PolicyTunnelMaxReadBytes, tunnelMaxWriteBytes: opts.PolicyTunnelMaxWriteBytes}
	if opts.PolicyMaxConnections > 0 {
		limits.connections = make(chan struct{}, opts.PolicyMaxConnections)
	}
	if opts.PolicyMaxInflight > 0 {
		limits.requests = make(chan struct{}, opts.PolicyMaxInflight)
	}
	if opts.PolicyMaxTunnels > 0 {
		limits.tunnels = make(chan struct{}, opts.PolicyMaxTunnels)
	}
	return limits, nil
}

func acquirePolicySlot(ctx context.Context, slots chan struct{}) (func(), bool) {
	if ctx.Err() != nil {
		return nil, false
	}
	if slots == nil {
		return func() {}, true
	}
	select {
	case slots <- struct{}{}:
		var once sync.Once
		return func() { once.Do(func() { <-slots }) }, true
	default:
		return nil, false
	}
}

func writePolicyOverloaded(w http.ResponseWriter) {
	w.Header().Set("Connection", "close")
	w.Header().Set("X-Proxy-Error", "overloaded")
	http.Error(w, "policy resource limit exceeded", http.StatusServiceUnavailable)
}

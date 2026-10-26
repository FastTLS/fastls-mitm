package main

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestPolicyResourceConfigurationFailsBeforeCA(t *testing.T) {
	for _, config := range []NewMITMProxyOptions{
		{PolicyMaxInflight: 1}, {PolicyMaxTunnels: 1}, {PolicyTunnelMaxAge: time.Second},
		{AddressPolicyFile: "missing", PolicyMaxInflight: -1}, {AddressPolicyFile: "missing", PolicyMaxInflight: 65537},
		{AddressPolicyFile: "missing", PolicyMaxTunnels: -1}, {AddressPolicyFile: "missing", PolicyMaxTunnels: 65537},
		{AddressPolicyFile: "missing", PolicyTunnelMaxAge: -1}, {AddressPolicyFile: "missing", PolicyTunnelMaxAge: 24*time.Hour + 1},
	} {
		config.CACertPath = filepath.Join(t.TempDir(), "ca.pem")
		config.CAKeyPath = config.CACertPath + ".key"
		if _, err := newPolicyLimits(config); err == nil {
			t.Fatal("invalid resource configuration accepted", config)
		}
		if _, err := NewMITMProxyWithOptions(config); err == nil {
			t.Fatal("invalid startup accepted")
		}
		if _, err := os.Stat(config.CACertPath); !os.IsNotExist(err) {
			t.Fatal("invalid startup created CA material")
		}
	}
	if _, err := newPolicyLimits(NewMITMProxyOptions{AddressPolicyFile: "trusted", PolicyMaxInflight: 65536, PolicyMaxTunnels: 65536, PolicyTunnelMaxAge: 24 * time.Hour}); err != nil {
		t.Fatal(err)
	}
}

func TestPolicySlotsAreNonblockingCancelableAndReleaseOnce(t *testing.T) {
	for _, slots := range []chan struct{}{nil, make(chan struct{}, 1)} {
		release, ok := acquirePolicySlot(context.Background(), slots)
		if !ok {
			t.Fatal("initial admission rejected")
		}
		if slots != nil {
			if _, ok := acquirePolicySlot(context.Background(), slots); ok {
				t.Fatal("overload admitted")
			}
		}
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); release() }()
		}
		wg.Wait()
		release, ok = acquirePolicySlot(context.Background(), slots)
		if !ok {
			t.Fatal("permit leaked")
		}
		release()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, ok := acquirePolicySlot(ctx, slots); ok {
			t.Fatal("canceled admission accepted")
		}
	}
}

package main

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
)

// Admission happens before HTTP parsing, so excess TCP connections cannot be
// promised an HTTP 503. Accepted idle and hijacked connections retain a lease.
type policyLimitedListener struct {
	net.Listener
	slots    chan struct{}
	onReject func()
}

func (l *policyLimitedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		release, ok := acquirePolicySlot(context.Background(), l.slots)
		if !ok {
			if l.onReject != nil {
				l.onReject()
			}
			_ = conn.Close()
			continue
		}
		return &policyLeasedConn{Conn: conn, release: release}, nil
	}
}

type policyLeasedConn struct {
	net.Conn
	release  func()
	once     sync.Once
	closeErr error
}

func (c *policyLeasedConn) Close() error {
	c.once.Do(func() { c.closeErr = c.Conn.Close(); c.release() })
	return c.closeErr
}

var errPolicyTrafficLimit = errors.New("policy tunnel traffic limit reached")

// Budgets are independent per direction, not one shared pool. In particular a
// background Read must never reserve capacity needed by a concurrent TLS Write.
// The wrapper is installed AFTER CONNECT 200, but OUTSIDE the TLS server and
// buffered ClientHello reader: handshake and prebuffered bytes are counted too.
type policyTrafficConn struct {
	onLimit func()
	net.Conn
	readMu         sync.Mutex
	writeMu        sync.Mutex
	readRemaining  int64 // -1 means unlimited
	writeRemaining int64
}

func newPolicyTrafficConn(conn net.Conn, read, write int64) *policyTrafficConn {
	if read == 0 {
		read = -1
	}
	if write == 0 {
		write = -1
	}
	return &policyTrafficConn{Conn: conn, readRemaining: read, writeRemaining: write}
}

func (c *policyTrafficConn) Read(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.readRemaining == 0 {
		return 0, errPolicyTrafficLimit
	}
	if c.readRemaining > 0 && int64(len(data)) > c.readRemaining {
		data = data[:int(c.readRemaining)]
	}
	n, err := c.Conn.Read(data)
	if c.readRemaining > 0 {
		c.readRemaining -= int64(n)
		if c.readRemaining == 0 {
			if c.onLimit != nil {
				c.onLimit()
			}
			_ = c.Close()
		}
	}
	return n, err
}

func (c *policyTrafficConn) Write(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeRemaining == 0 {
		return 0, errPolicyTrafficLimit
	}
	wanted := len(data)
	if c.writeRemaining > 0 && int64(len(data)) > c.writeRemaining {
		data = data[:int(c.writeRemaining)]
	}
	n, err := c.Conn.Write(data)
	if c.writeRemaining > 0 {
		c.writeRemaining -= int64(n)
		if c.writeRemaining == 0 {
			if c.onLimit != nil {
				c.onLimit()
			}
			_ = c.Close()
		}
	}
	if err == nil && n != wanted {
		if c.writeRemaining == 0 {
			err = errPolicyTrafficLimit
		} else {
			err = io.ErrShortWrite
		}
	}
	return n, err
}

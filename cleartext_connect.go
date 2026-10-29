package main

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type tunnelReadAheadConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *tunnelReadAheadConn) Read(data []byte) (int, error) { return c.reader.Read(data) }

// CONNECT does not imply TLS. Preserve read-ahead while identifying a TLS
// handshake or an HTTP/1 request; the inner parser still validates the request.
func readTunnelProtocol(ctx context.Context, conn net.Conn) (net.Conn, bool, error) {
	if err := conn.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return nil, false, err
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	reader := bufio.NewReader(conn)
	first, err := reader.Peek(1)
	if err != nil {
		return nil, false, err
	}
	if err = conn.SetReadDeadline(time.Time{}); err != nil {
		return nil, false, err
	}
	return &tunnelReadAheadConn{Conn: conn, reader: reader}, first[0] == 22, nil
}

func (p *MITMProxy) serveCleartextCONNECT(conn net.Conn, outer *Context, host string, config *RequestFingerprintConfig, parent *url.URL) {
	p.delegate.BeforeRequest(outer)
	if outer.Aborted {
		return
	}
	if parent == nil {
		var err error
		parent, err = p.delegate.ParentProxy(outer.Req)
		if err != nil {
			return
		}
	}
	outer.Data["host"], outer.Data["scheme"] = host, "http"
	outer.Data["requestConfig"], outer.Data["parentProxy"] = config, parent
	p.serveDefaultTunnel(conn, outer)
}

func boundCleartextRequest(req *http.Request, host string) bool {
	if req.Method == http.MethodConnect || req.Header.Get("Upgrade") != "" {
		return false
	}
	base, err := url.Parse("http://" + host)
	if err != nil {
		return false
	}
	actual, err := url.Parse("http://" + req.Host)
	if err != nil || actual.User != nil || actual.Path != "" || actual.Host != req.Host || actual.RawQuery != "" || actual.Fragment != "" || actual.ForceQuery {
		return false
	}
	port := func(u *url.URL) string {
		if u.Port() != "" {
			return u.Port()
		}
		return "80"
	}
	if !equalTunnelHost(base.Hostname(), actual.Hostname()) || port(base) != port(actual) {
		return false
	}
	return (req.URL.Scheme == "" || req.URL.Scheme == "http") && (req.URL.Host == "" || req.URL.Host == req.Host)
}

func equalTunnelHost(a, b string) bool {
	left, right := net.ParseIP(a), net.ParseIP(b)
	if left != nil && right != nil {
		return left.Equal(right)
	}
	return strings.EqualFold(a, b)
}

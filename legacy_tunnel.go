package main

import (
	"context"
	"crypto/tls"
	"errors"
	"github.com/FastTLS/fastls-mitm/internal/audit"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FastTLS/ftransport"
	utls "github.com/refraction-networking/utls"
)

// The inner HTTP server owns reading the decrypted connection. Its background
// read cancels a request on peer disconnect even while RoundTrip waits for
// headers. A synchronous ReadRequest/RoundTrip loop cannot observe that EOF.
func (p *MITMProxy) serveDefaultTunnel(clientConn net.Conn, outer *Context) {
	var upstream net.Conn
	defer func() {
		if upstream != nil {
			upstream.Close()
		}
	}()
	var transport *ftransport.Transport
	var upstreamH2 bool
	defer func() {
		if transport != nil {
			_ = transport.Close()
		}
	}()
	listener := &policySingleListener{conn: clientConn, done: make(chan struct{})}
	server := &http.Server{
		ReadHeaderTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second,
		BaseContext: func(net.Listener) context.Context { return outer.Req.Context() },
		ConnState: func(_ net.Conn, state http.ConnState) {
			if state == http.StateClosed {
				listener.Close()
			}
		},
		Handler: p.audit.HTTP("mitm", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			timeout := 30 * time.Second
			if outer.Options != nil && outer.Options.Timeout > 0 {
				timeout = time.Duration(outer.Options.Timeout) * time.Second
			}
			ctx, cancel := context.WithTimeout(req.Context(), timeout)
			defer cancel()
			req = req.WithContext(ctx)
			deadline, _ := ctx.Deadline()
			_ = http.NewResponseController(w).SetReadDeadline(deadline)
			config := parseFingerprintFromHeaders(req.Header)
			if !config.Override {
				config, _ = outer.Data["requestConfig"].(*RequestFingerprintConfig)
			}
			parent, err := parseProxyFromHeaders(req.Header)
			if err != nil {
				http.Error(w, "invalid parent proxy", http.StatusBadRequest)
				return
			}
			if parent == nil {
				parent, _ = outer.Data["parentProxy"].(*url.URL)
			}
			host := outer.Data["host"].(string)
			modified, order, pseudo, settings := p.modifyRequestHeaders(req, host, config)
			modified.URL.Scheme, modified.URL.Host = "https", host
			modified.RequestURI = ""
			modified.Header = policyHeaders(modified.Header)
			modified.Header.Del("Host") // authority belongs to Request.Host
			if transport == nil {
				force, _ := outer.Data["forceProtocol"].(string)
				conn, err := p.dialTLSWithFingerprint(ctx, "tcp", host, force, config, parent)
				if err != nil {
					http.Error(w, "upstream connection failed", http.StatusBadGateway)
					return
				}
				protocol := "http/1.1"
				switch c := conn.(type) {
				case *tls.Conn:
					if c.ConnectionState().NegotiatedProtocol == "h2" {
						protocol = "h2"
					}
				case *utls.UConn:
					if c.ConnectionState().NegotiatedProtocol == "h2" {
						protocol = "h2"
					}
				}
				upstream = &tunnelOwnedConn{Conn: conn}
				transport, err = newTunnelTransport(upstream, protocol, settings, func(ctx context.Context) (net.Conn, error) {
					selectedForce := force
					if protocol == "http/1.1" {
						selectedForce = "http/1.1"
					}
					return p.dialTLSWithFingerprint(ctx, "tcp", host, selectedForce, config, parent)
				})
				upstreamH2 = protocol == "h2"
				if err != nil {
					upstream.Close()
					http.Error(w, "upstream transport failed", http.StatusBadGateway)
					return
				}
			}
			if !upstreamH2 {
				pseudo = nil
			}
			prepared, err := withRequestOrder(modified, order, pseudo)
			if err != nil {
				http.Error(w, "invalid request order", http.StatusBadRequest)
				return
			}
			response, err := roundTripDefaultTunnel(transport, prepared)
			if err != nil {
				code, phase := audit.Error(err, "request_error")
				audit.Result(ctx, "", 0, code, phase)
				logError("upstream request failed: %v", err)
				w.Header().Set("Connection", "close")
				http.Error(w, "upstream request failed", http.StatusBadGateway)
				return
			}
			audit.Result(ctx, response.Proto, response.StatusCode, "", "")
			defer response.Body.Close()
			writeProxyResponse(w, response)
		})),
	}
	defer server.Close()
	_ = server.Serve(listener)
}

// A peer may close a pooled connection while the next request acquires it.
// Replay only bodyless safe methods, once, before any response is returned.
// The same transport preserves the dial policy and original request deadline.
func roundTripDefaultTunnel(transport http.RoundTripper, request *http.Request) (*http.Response, error) {
	var reused atomic.Bool
	trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { reused.Store(info.Reused) }}
	traced := request.WithContext(httptrace.WithClientTrace(request.Context(), trace))
	response, err := transport.RoundTrip(traced)
	if response != nil || err == nil || !reused.Load() || request.Context().Err() != nil ||
		(request.Method != http.MethodGet && request.Method != http.MethodHead) ||
		(request.Body != nil && request.Body != http.NoBody) || request.ContentLength > 0 ||
		len(request.TransferEncoding) != 0 || len(request.Trailer) != 0 ||
		(!errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF)) {
		return response, err
	}
	if closer, ok := transport.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
	return transport.RoundTrip(traced)
}

// Transfer ownership of the already fingerprinted TLS connection. The
// transport supplies protocol framing, header order, trailers and cancellation.
func newTunnelTransport(conn net.Conn, protocol string, settings *ftransport.HTTP2Config, redial func(context.Context) (net.Conn, error)) (*ftransport.Transport, error) {
	selected := ftransport.ProtocolHTTP1
	if protocol == "h2" {
		selected = ftransport.ProtocolHTTP2
	}
	config := ftransport.Config{Protocols: []ftransport.Protocol{selected}}
	if settings != nil && selected == ftransport.ProtocolHTTP2 {
		config.HTTP2 = *settings
	}
	claimed := false
	var mu sync.Mutex
	config.DialContext = func(ctx context.Context, request ftransport.DialRequest) (ftransport.DialResult, error) {
		mu.Lock()
		initial := !claimed
		claimed = true
		mu.Unlock()
		if err := ctx.Err(); err != nil {
			return ftransport.DialResult{}, err
		}
		candidate := conn
		negotiated := protocol
		if !initial {
			var err error
			candidate, err = redial(ctx)
			if err != nil {
				return ftransport.DialResult{}, err
			}
			switch c := candidate.(type) {
			case *tls.Conn:
				negotiated = c.ConnectionState().NegotiatedProtocol
			case *utls.UConn:
				negotiated = c.ConnectionState().NegotiatedProtocol
			}
			if negotiated == "" {
				negotiated = "http/1.1"
			}
		}
		return ftransport.DialResult{Conn: candidate, NegotiatedProtocol: negotiated, TLSState: &tls.ConnectionState{HandshakeComplete: true, NegotiatedProtocol: negotiated, NegotiatedProtocolIsMutual: true}}, nil
	}
	return ftransport.NewTransport(config)
}

func writeProxyResponse(w http.ResponseWriter, response *http.Response) {
	if response.Request != nil {
		if deadline, ok := response.Request.Context().Deadline(); ok {
			_ = http.NewResponseController(w).SetWriteDeadline(deadline)
		}
	}
	if response.Close {
		w.Header().Set("Connection", "close")
	}
	headers := policyHeaders(response.Header)
	declared := make(map[string]bool, len(response.Trailer))
	if len(response.Trailer) > 0 {
		headers.Del("Content-Length")
		for name := range response.Trailer {
			headers.Add("Trailer", name)
			declared[http.CanonicalHeaderKey(name)] = true
		}
	}
	for name, values := range headers {
		w.Header()[name] = append([]string(nil), values...)
	}
	w.WriteHeader(response.StatusCode)
	// Streaming headers must reach the peer before waiting for more body data.
	_ = http.NewResponseController(w).Flush()
	if _, err := io.Copy(w, response.Body); err != nil {
		if response.Request != nil {
			code, phase := audit.Error(err, "read_error")
			audit.Result(response.Request.Context(), "", 0, code, phase)
		}
		panic(http.ErrAbortHandler)
	}
	for name, values := range response.Trailer {
		if !declared[http.CanonicalHeaderKey(name)] {
			name = http.TrailerPrefix + name
		}
		w.Header()[name] = append([]string(nil), values...)
	}
}

type tunnelOwnedConn struct {
	net.Conn
	once sync.Once
	err  error
}

func (c *tunnelOwnedConn) Close() error { c.once.Do(func() { c.err = c.Conn.Close() }); return c.err }

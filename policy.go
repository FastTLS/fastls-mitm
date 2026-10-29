package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"github.com/FastTLS/fastls-mitm/internal/audit"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	fastls "github.com/FastTLS/fastls"
	"github.com/FastTLS/fastls-mitm/internal/servicepolicy"
)

const policyDefaultRequestBytes = 4 << 20

type mitmAddressPolicy interface {
	CheckAddressPolicy(context.Context, *http.Request, string) error
	DoContext(context.Context, string, fastls.Options, string) (fastls.Response, error)
}

func loadMITMAddressPolicy(path string, maximum int64) (mitmAddressPolicy, int64, error) {
	if path == "" {
		if maximum != 0 {
			return nil, 0, errors.New("policy-max-request-bytes requires address-policy")
		}
		return nil, policyDefaultRequestBytes, nil
	}
	if maximum == 0 {
		maximum = policyDefaultRequestBytes
	}
	if maximum < 1 || maximum > 64<<20 {
		return nil, 0, errors.New("policy-max-request-bytes must be 1..67108864 (0 selects the 4 MiB default)")
	}
	client, err := servicepolicy.Load(fastls.NewClient(), path)
	if err != nil {
		return nil, 0, err
	}
	guard, ok := any(client).(mitmAddressPolicy)
	if !ok {
		return nil, 0, errors.New("MITM address policy requires core preflight and origin-binding capability; refusing to start")
	}
	return guard, maximum, nil
}

type proxyPolicyError string

func (e proxyPolicyError) Error() string               { return "address policy denied request: " + string(e) }
func (e proxyPolicyError) AddressPolicyReason() string { return string(e) }

func policyReason(err error) (string, bool) {
	var denied interface{ AddressPolicyReason() string }
	if errors.As(err, &denied) {
		return denied.AddressPolicyReason(), true
	}
	return "", false
}

func writePolicyError(w http.ResponseWriter, ctx context.Context, err error) {
	code, phase := audit.Error(err, "request_error")
	audit.Result(ctx, "", 0, code, phase)
	if reason, ok := policyReason(err); ok {
		w.Header().Set("X-Proxy-Error", "address_denied")
		w.Header().Set("X-Proxy-Error-Reason", reason)
		http.Error(w, "address policy denied request: "+reason, http.StatusForbidden)
		return
	}
	w.Header().Set("X-Proxy-Error", "upstream_error")
	http.Error(w, "upstream request failed", http.StatusBadGateway)
}

func policyHeaders(source http.Header) http.Header {
	out := source.Clone()
	drop := map[string]bool{}
	for _, value := range source.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			drop[strings.ToLower(strings.TrimSpace(name))] = true
		}
	}
	// Also honor non-canonical Connection map keys supplied by trusted hooks.
	for key, values := range source {
		if key != "Connection" && strings.EqualFold(key, "Connection") {
			for _, value := range values {
				for _, name := range strings.Split(value, ",") {
					drop[strings.ToLower(strings.TrimSpace(name))] = true
				}
			}
		}
	}
	for _, name := range []string{"Connection", "Proxy-Connection", "Proxy-Authorization", "Proxy-Authenticate", "Keep-Alive", "Transfer-Encoding", "TE", "Trailer", "Upgrade"} {
		drop[strings.ToLower(name)] = true
	}
	for name := range out {
		if drop[strings.ToLower(name)] || strings.HasPrefix(strings.ToLower(name), "x-mitm-") {
			delete(out, name)
		}
	}
	return out
}

func (p *MITMProxy) policyControls(ctx *Context) error {
	r := ctx.Req
	if r.Method == http.MethodConnect || r.Header.Get("Upgrade") != "" || strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") {
		return proxyPolicyError("upgrade_unsupported")
	}
	if r.Header.Get("X-Mitm-Proxy") != "" || ctx.Options.Proxy != "" {
		return proxyPolicyError("proxy_unsupported")
	}
	if r.Header.Get("X-Mitm-Force-HTTP11") == "true" {
		return proxyPolicyError("force_protocol_unsupported")
	}
	parent, err := p.delegate.ParentProxy(r)
	if err != nil {
		return errors.New("parent proxy selection failed")
	}
	if parent != nil {
		return proxyPolicyError("proxy_unsupported")
	}
	return nil
}

// Policy mode never enters the raw dialer, hand-written HTTP writer or
// transparent tunnel fallback. Each bounded HTTP request goes through core.
func (p *MITMProxy) handlePolicyHTTP(w http.ResponseWriter, r *http.Request, origin string) {
	requestCtx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	ctx := NewContext(r.Clone(requestCtx))
	// The inbound body reader fills r.Trailer at EOF. A Request.Clone would
	// otherwise freeze the initial empty trailer values before the bounded read.
	ctx.Req.Trailer = r.Trailer
	defer p.delegate.Finish(ctx)
	if r.Body != nil {
		defer r.Body.Close()
	}
	ctx.Data["mitm.policy.connect_authenticated"] = origin != ""
	// Proxy authentication belongs to CONNECT, not to the encrypted origin
	// request, which must not need or forward proxy credentials again.
	if origin == "" && !p.delegate.Auth(ctx, w) {
		w.Header().Set("Proxy-Authenticate", "Basic realm=\"Proxy\"")
		w.WriteHeader(http.StatusProxyAuthRequired)
		return
	}
	if ctx.Aborted {
		return
	}
	release, admitted := acquirePolicySlot(requestCtx, p.policyLimits.requests)
	if !admitted {
		writePolicyOverloaded(w)
		return
	}
	defer release()
	if ctx.Req.URL.Scheme == "" {
		if origin != "" {
			base, err := url.Parse(origin)
			if err != nil {
				writePolicyError(w, r.Context(), proxyPolicyError("invalid_origin"))
				return
			}
			ctx.Req.URL.Scheme = base.Scheme
			if ctx.Req.URL.Host == "" {
				ctx.Req.URL.Host = base.Host
			}
		} else {
			ctx.Req.URL.Scheme = "http"
			if ctx.Req.URL.Host == "" {
				ctx.Req.URL.Host = ctx.Req.Host
			}
		}
	}
	ctx.Options.HeaderValues = policyHeaders(ctx.Req.Header)
	ctx.Options.HeaderValues["Host"] = []string{ctx.Req.Host}
	ctx.Options.VerifyTLS = p.verifyTargetCert
	if ctx.Req.URL.Scheme == "https" {
		p.applyImitateConfig(ctx.Options, parseFingerprintFromHeaders(ctx.Req.Header))
	}
	p.delegate.BeforeRequest(ctx)
	if ctx.Aborted {
		return
	}
	if ctx.Options == nil || ctx.Req == nil || ctx.Req.URL == nil {
		writePolicyError(w, r.Context(), proxyPolicyError("invalid_request"))
		return
	}
	if err := p.policyControls(ctx); err != nil {
		code, phase := audit.Error(err, "request_error")
		audit.Result(r.Context(), "", 0, code, phase)
		writePolicyError(w, r.Context(), err)
		return
	}
	if ctx.Req.ContentLength > p.policyMaxRequestBytes {
		w.Header().Set("Connection", "close")
		w.Header().Set("X-Proxy-Error", "request_too_large")
		http.Error(w, "request exceeds policy byte limit", http.StatusRequestEntityTooLarge)
		return
	}
	if err := p.policy.CheckAddressPolicy(ctx.Req.Context(), ctx.Req, origin); err != nil {
		code, phase := audit.Error(err, "request_error")
		audit.Result(r.Context(), "", 0, code, phase)
		writePolicyError(w, r.Context(), err)
		return
	}
	// Read through EOF before forwarding, so chunked request trailers have
	// complete values. This opt-in mode deliberately has a finite body budget.
	body := ctx.Req.Body
	if body == nil {
		body = http.NoBody
	}
	body = http.MaxBytesReader(w, body, p.policyMaxRequestBytes)
	data, err := io.ReadAll(body)
	if err != nil {
		w.Header().Set("Connection", "close")
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			w.Header().Set("X-Proxy-Error", "request_too_large")
			http.Error(w, "request exceeds policy byte limit", http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, "invalid request body", http.StatusBadRequest)
		}
		return
	}
	options := *ctx.Options
	options.Headers = clonePolicyStrings(options.Headers)
	options.HeaderValues = policyHeaders(http.Header(options.HeaderValues))
	for name, value := range options.Headers {
		if strings.HasPrefix(strings.ToLower(name), "x-mitm-") {
			delete(options.Headers, name)
			continue
		}
		// Profile normalization mirrors the first HeaderValues item into
		// Headers. That mirror is not a delegate edit and must not flatten
		// repeated caller fields (including in decrypted CONNECT requests).
		unchanged := false
		for existing, values := range options.HeaderValues {
			if strings.EqualFold(existing, name) && len(values) > 0 && values[0] == value {
				unchanged = true
				break
			}
		}
		if unchanged {
			continue
		}
		// Explicit delegate header edits override the copied multi-value view.
		for existing := range options.HeaderValues {
			if strings.EqualFold(existing, name) {
				delete(options.HeaderValues, existing)
			}
		}
		if options.HeaderValues == nil {
			options.HeaderValues = make(map[string][]string)
		}
		options.HeaderValues[name] = []string{value}
	}
	options.Headers = nil
	options.HeaderValues = policyHeaders(http.Header(options.HeaderValues))
	// Recheck the effective Host after delegate Options edits in the actual
	// core request; never replace its URL with the CONNECT host to hide mismatch.
	if options.HeaderValues == nil {
		options.HeaderValues = make(map[string][]string)
	}
	hasHost := false
	for name := range options.HeaderValues {
		if strings.EqualFold(name, "Host") {
			hasHost = true
		}
		if strings.EqualFold(name, "Content-Length") || strings.EqualFold(name, "Expect") {
			delete(options.HeaderValues, name)
		}
	}
	if !hasHost {
		options.HeaderValues["Host"] = []string{ctx.Req.Host}
	}
	if options.Body == "" {
		options.Body = string(data)
	}
	options.Trailers = ctx.Req.Trailer.Clone()
	options.DisableRedirect = true // A proxy returns 3xx; the caller chooses the next request.
	response, err := p.policy.DoContext(ctx.Req.Context(), ctx.Req.URL.String(), options, ctx.Req.Method)
	defer response.Client.CloseIdleConnections()
	if response.Body != nil {
		defer response.Body.Close()
	}
	var out *http.Response
	if err == nil {
		out = &http.Response{StatusCode: response.Status, Header: http.Header(response.HeaderValues).Clone(), Trailer: response.Trailer, Body: response.Body}
	}
	if err != nil {
		code, phase := audit.Error(err, "request_error")
		audit.Result(r.Context(), response.Protocol, response.Status, code, phase)
	} else {
		audit.Result(r.Context(), response.Protocol, response.Status, "", "")
	}
	if out != nil {
		out.Request = ctx.Req
	}
	p.delegate.BeforeResponse(ctx, out, err)
	if ctx.Aborted {
		return
	}
	if err != nil {
		code, phase := audit.Error(err, "request_error")
		audit.Result(r.Context(), "", 0, code, phase)
		writePolicyError(w, r.Context(), err)
		return
	}
	if out == nil || out.Body == nil {
		writePolicyError(w, r.Context(), errors.New("empty upstream response"))
		return
	}
	if out.StatusCode == http.StatusSwitchingProtocols {
		writePolicyError(w, r.Context(), proxyPolicyError("upgrade_unsupported"))
		return
	}
	writeProxyResponse(w, out)
}

func clonePolicyStrings(source map[string]string) map[string]string {
	out := make(map[string]string, len(source))
	for name, value := range source {
		out[name] = value
	}
	return out
}

func (p *MITMProxy) handlePolicyConnect(w http.ResponseWriter, r *http.Request) {
	ctx := NewContext(r)
	defer p.delegate.Finish(ctx)
	p.delegate.Connect(ctx, w)
	if ctx.Aborted {
		return
	}
	if !p.delegate.Auth(ctx, w) {
		w.Header().Set("Proxy-Authenticate", "Basic realm=\"Proxy\"")
		w.WriteHeader(http.StatusProxyAuthRequired)
		return
	}
	if ctx.Aborted {
		return
	}
	if p.disableConnect {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	release, admitted := acquirePolicySlot(r.Context(), p.policyLimits.tunnels)
	if !admitted {
		writePolicyOverloaded(w)
		return
	}
	defer release()
	if r.Header.Get("X-Mitm-Proxy") != "" {
		writePolicyError(w, r.Context(), proxyPolicyError("proxy_unsupported"))
		return
	}
	if r.Header.Get("Upgrade") != "" || strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") {
		writePolicyError(w, r.Context(), proxyPolicyError("upgrade_unsupported"))
		return
	}
	if r.Header.Get("X-Mitm-Force-HTTP11") == "true" {
		writePolicyError(w, r.Context(), proxyPolicyError("force_protocol_unsupported"))
		return
	}
	parent, err := p.delegate.ParentProxy(r)
	if err != nil {
		writePolicyError(w, r.Context(), errors.New("parent proxy selection failed"))
		return
	}
	if parent != nil {
		writePolicyError(w, r.Context(), proxyPolicyError("proxy_unsupported"))
		return
	}
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}
	u, err := url.Parse("https://" + host)
	if err != nil || u.Host != host || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.User != nil || r.ContentLength > 0 || len(r.TransferEncoding) > 0 {
		writePolicyError(w, r.Context(), proxyPolicyError("invalid_connect_authority"))
		return
	}
	origin := u.String()
	probe := &http.Request{URL: u, Host: host}
	if err = p.policy.CheckAddressPolicy(r.Context(), probe, origin); err != nil {
		// CONNECT carries an authority, not an application scheme. Admit an
		// HTTP-only policy only on a scheme rejection, then bind and recheck
		// the actual protocol before any origin connection is created.
		var reason interface{ AddressPolicyReason() string }
		if errors.As(err, &reason) && reason.AddressPolicyReason() == "scheme_not_allowed" {
			u.Scheme = "http"
			origin = u.String()
			err = p.policy.CheckAddressPolicy(r.Context(), probe, origin)
		}
	}
	if err != nil {
		code, phase := audit.Error(err, "request_error")
		audit.Result(r.Context(), "", 0, code, phase)
		writePolicyError(w, r.Context(), err)
		return
	}
	cert, err := p.getCertForHost(u.Hostname())
	if err != nil {
		http.Error(w, "cannot prepare tunnel certificate", 500)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking unavailable", 500)
		return
	}
	raw, buffered, err := hijacker.Hijack()
	if err != nil {
		return
	}
	tunnelCtx, cancel := context.WithCancel(r.Context())
	// Preserve bytes already read past CONNECT, then detach from net/http's
	// old connReader. Reusing it would let the inner server's normal read
	// deadline interruption cancel the outer CONNECT request's context.
	prefix := make([]byte, buffered.Reader.Buffered())
	if _, err = io.ReadFull(buffered.Reader, prefix); err != nil {
		cancel()
		raw.Close()
		return
	}
	conn := &policyBufferedConn{Conn: raw, reader: io.MultiReader(bytes.NewReader(prefix), raw), cancel: cancel}
	defer conn.Close()
	if !p.trackTunnel(conn) {
		return
	}
	defer p.untrackTunnel(conn)
	if p.policyLimits.tunnelMaxAge > 0 {
		timer := time.AfterFunc(p.policyLimits.tunnelMaxAge, func() { _ = conn.Close() })
		defer timer.Stop()
	}
	if _, err = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	audit.Downstream(r.Context(), http.StatusOK)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{*cert}, NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12}
	tlsConfig.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if hello.ServerName == "" {
			return nil, nil
		}
		port := u.Port()
		if port == "" {
			port = "443"
		}
		address := net.JoinHostPort(hello.ServerName, port)
		check := &http.Request{URL: &url.URL{Scheme: "https", Host: address}, Host: address}
		return nil, p.policy.CheckAddressPolicy(hello.Context(), check, origin)
	}
	var tlsWire net.Conn = conn
	if p.policyLimits.tunnelMaxReadBytes > 0 || p.policyLimits.tunnelMaxWriteBytes > 0 {
		traffic := newPolicyTrafficConn(conn, p.policyLimits.tunnelMaxReadBytes, p.policyLimits.tunnelMaxWriteBytes)
		traffic.onLimit = func() { audit.Result(tunnelCtx, "", 0, "traffic_limited", "") }
		tlsWire = traffic
	}
	applicationConn, encrypted, err := readTunnelProtocol(tunnelCtx, tlsWire)
	if err != nil {
		return
	}
	u.Scheme = "http"
	if encrypted {
		u.Scheme = "https"
	}
	origin = u.String()
	if err = p.policy.CheckAddressPolicy(tunnelCtx, probe, origin); err != nil {
		audit.Result(tunnelCtx, "", 0, "address_denied", "")
		return
	}
	if encrypted {
		tlsConn := tls.Server(applicationConn, tlsConfig)
		handshakeCtx, stop := context.WithTimeout(tunnelCtx, 30*time.Second)
		err = tlsConn.HandshakeContext(handshakeCtx)
		stop()
		if err != nil {
			return
		}
		applicationConn = tlsConn
	}
	listener := &policySingleListener{conn: applicationConn, done: make(chan struct{})}
	server := &http.Server{
		MaxHeaderBytes: 64 << 10, ReadHeaderTimeout: 30 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second,
		BaseContext: func(net.Listener) context.Context { return tunnelCtx },
		ConnState: func(_ net.Conn, state http.ConnState) {
			if state == http.StateClosed {
				listener.Close()
			}
		},
		Handler: p.audit.HTTP("mitm", http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			if !parseFingerprintFromHeaders(request.Header).Override {
				for _, name := range []string{"X-Mitm-Browser", "X-Mitm-Ja3", "X-Mitm-Ja4r", "X-Mitm-H2Settings"} {
					if value := r.Header.Get(name); value != "" {
						request.Header.Set(name, value)
					}
				}
			}
			p.handlePolicyHTTP(w, request, origin)
		})),
	}
	defer server.Close()
	_ = server.Serve(listener)
}

type policyBufferedConn struct {
	net.Conn
	reader io.Reader
	cancel context.CancelFunc
	once   sync.Once
}

func (c *policyBufferedConn) Read(data []byte) (int, error) { return c.reader.Read(data) }
func (c *policyBufferedConn) Close() error                  { c.once.Do(c.cancel); return c.Conn.Close() }

type policySingleListener struct {
	conn    net.Conn
	done    chan struct{}
	mu      sync.Mutex
	claimed bool
	once    sync.Once
}

func (l *policySingleListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if !l.claimed {
		l.claimed = true
		l.mu.Unlock()
		return l.conn, nil
	}
	l.mu.Unlock()
	<-l.done
	return nil, net.ErrClosed
}
func (l *policySingleListener) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *policySingleListener) Addr() net.Addr { return l.conn.LocalAddr() }

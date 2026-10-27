package main

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	fastls "github.com/FastTLS/fastls"
	"github.com/sirupsen/logrus"
)

// CertCache 证书缓存接口
type CertCache interface {
	Set(host string, cert *tls.Certificate)
	Get(host string) *tls.Certificate
}

// DefaultCertCache 默认内存证书缓存
type DefaultCertCache struct {
	certCache map[string]*tls.Certificate
	certMutex sync.RWMutex
}

func NewDefaultCertCache() *DefaultCertCache {
	return &DefaultCertCache{
		certCache: make(map[string]*tls.Certificate),
	}
}

func (c *DefaultCertCache) Set(host string, cert *tls.Certificate) {
	c.certMutex.Lock()
	defer c.certMutex.Unlock()
	c.certCache[host] = cert
}

func (c *DefaultCertCache) Get(host string) *tls.Certificate {
	c.certMutex.RLock()
	defer c.certMutex.RUnlock()
	return c.certCache[host]
}

type MITMProxy struct {
	policy                mitmAddressPolicy
	policyMaxRequestBytes int64
	policyLimits          policyLimits
	caCert                *x509.Certificate
	caKey                 *rsa.PrivateKey
	caCertPEM             []byte
	caKeyPEM              []byte
	caCertPath            string
	caKeyPath             string
	server                *http.Server
	serverMu              sync.Mutex
	tunnelMu              sync.Mutex
	tunnels               map[net.Conn]struct{}
	tunnelClosing         bool
	certCache             CertCache
	fingerprint           fastls.Fingerprint
	browser               string
	listenAddr            string
	disableConnect        bool
	verifyTargetCert      bool // 是否验证目标服务器证书
	proxyTLSRootCAs       *x509.CertPool
	delegate              Delegate
}

// NewMITMProxyOptions MITMProxy 配置选项
type NewMITMProxyOptions struct {
	// AddressPolicyFile is trusted startup configuration, never a request header.
	AddressPolicyFile string
	// PolicyMaxRequestBytes is 0 for the policy-mode default of 4 MiB.
	PolicyMaxRequestBytes int64
	// Policy resource limits are opt-in startup settings; zero disables each.
	PolicyMaxInflight         int
	PolicyMaxTunnels          int
	PolicyTunnelMaxAge        time.Duration
	PolicyMaxConnections      int
	PolicyTunnelMaxReadBytes  int64
	PolicyTunnelMaxWriteBytes int64
	ListenAddr                string
	Fingerprint               fastls.Fingerprint
	Browser                   string
	DisableConnect            bool
	VerifyTargetCert          bool // 是否验证目标服务器证书
	Delegate                  Delegate
	CertCache                 CertCache
	// CACertPath and CAKeyPath override the default on-disk CA paths. They are
	// primarily useful for isolated development and test instances.
	CACertPath string
	CAKeyPath  string
	// ProxyTLSRootCAs optionally replaces system roots for HTTPS parent proxies.
	ProxyTLSRootCAs *x509.CertPool
}

// NewMITMProxy 创建 MITM 代理服务器
func NewMITMProxy(listenAddr string, fingerprint fastls.Fingerprint, browser string, disableConnect bool) (*MITMProxy, error) {
	return NewMITMProxyWithOptions(NewMITMProxyOptions{
		ListenAddr:       listenAddr,
		Fingerprint:      fingerprint,
		Browser:          browser,
		DisableConnect:   disableConnect,
		VerifyTargetCert: false, // 默认不验证目标服务器证书
		Delegate:         &DefaultDelegate{},
		CertCache:        NewDefaultCertCache(),
	})
}

// NewMITMProxyWithOptions 使用配置选项创建 MITM 代理服务器
func NewMITMProxyWithOptions(opts NewMITMProxyOptions) (*MITMProxy, error) {
	limits, err := newPolicyLimits(opts)
	if err != nil {
		return nil, err
	}
	policy, maximum, err := loadMITMAddressPolicy(opts.AddressPolicyFile, opts.PolicyMaxRequestBytes)
	if err != nil {
		return nil, err
	}
	if opts.Delegate == nil {
		opts.Delegate = &DefaultDelegate{}
	}
	if opts.CertCache == nil {
		opts.CertCache = NewDefaultCertCache()
	}

	proxy := &MITMProxy{
		policy:                policy,
		policyMaxRequestBytes: maximum,
		policyLimits:          limits,
		certCache:             opts.CertCache,
		listenAddr:            opts.ListenAddr,
		fingerprint:           opts.Fingerprint,
		browser:               opts.Browser,
		disableConnect:        opts.DisableConnect,
		verifyTargetCert:      opts.VerifyTargetCert,
		delegate:              opts.Delegate,
		caCertPath:            opts.CACertPath,
		caKeyPath:             opts.CAKeyPath,
		proxyTLSRootCAs:       opts.ProxyTLSRootCAs,
		tunnels:               make(map[net.Conn]struct{}),
	}

	if err := proxy.generateCA(); err != nil {
		return nil, fmt.Errorf("生成CA证书失败: %v", err)
	}

	return proxy, nil
}

func (p *MITMProxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	if p.policy != nil {
		p.handlePolicyConnect(w, r)
		return
	}
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}

	// 创建上下文
	ctx := NewContext(r)
	defer p.delegate.Finish(ctx)

	// 调用 Delegate.Connect
	p.delegate.Connect(ctx, w)

	// 检查是否中止
	if ctx.Aborted {
		return
	}

	// CONNECT authentication must happen before hijacking and before sending
	// 200 Connection Established; otherwise a 407 response cannot reach the client.
	if !p.delegate.Auth(ctx, w) {
		logResponse("CONNECT", host, http.StatusProxyAuthRequired, "Proxy Authentication Required", nil)
		w.Header().Set("Proxy-Authenticate", "Basic realm=\"Proxy\"")
		w.WriteHeader(http.StatusProxyAuthRequired)
		return
	}

	// 解析指纹和代理信息
	requestConfig := parseFingerprintFromHeaders(r.Header)
	headerProxy, err := parseProxyFromHeaders(r.Header)
	if err != nil {
		http.Error(w, "Invalid X-Mitm-Proxy: "+err.Error(), http.StatusBadRequest)
		return
	}

	fingerprintInfo := formatFingerprintInfo(requestConfig)
	proxyInfo := ""
	if headerProxy != nil {
		proxyInfo = proxyURLForLog(headerProxy)
	}

	logRequest("CONNECT", host, fingerprintInfo, proxyInfo)
	logDebug("收到 CONNECT 请求: %s -> %s", r.RemoteAddr, host)

	if p.disableConnect {
		logResponse("CONNECT", host, http.StatusMethodNotAllowed, "Method Not Allowed", nil)
		logDebug("CONNECT 请求被禁用，返回 405 Method Not Allowed")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Proxy-Error", "CONNECT method not supported")
		w.WriteHeader(http.StatusMethodNotAllowed)
		errorMsg := fmt.Sprintf(
			"405 Method Not Allowed\r\n\r\n"+
				"此代理服务器不支持 CONNECT 隧道请求。\r\n"+
				"请使用 HTTP 代理方式发送请求，而不是 HTTPS 隧道模式。\r\n\r\n"+
				"示例:\r\n"+
				"  curl -x http://%s http://example.com/api\r\n"+
				"  而不是: curl -x http://%s https://example.com/api\r\n\r\n"+
				"注意: 禁用 CONNECT 后，无法通过代理访问 HTTPS 网站。\r\n",
			p.listenAddr, p.listenAddr)
		w.Write([]byte(errorMsg))
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		logResponse("CONNECT", host, http.StatusInternalServerError, "Internal Server Error", fmt.Errorf("Hijacking not supported"))
		logDebug("错误: 不支持Hijack")
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, buffered, err := hijacker.Hijack()
	if err != nil {
		logResponse("CONNECT", host, http.StatusInternalServerError, "Internal Server Error", err)
		logDebug("Hijack失败: %v", err)
		if clientConn != nil {
			clientConn.Write([]byte("HTTP/1.1 500 Internal Server Error\r\n\r\n"))
			clientConn.Close()
		}
		return
	}
	prefix := make([]byte, buffered.Reader.Buffered())
	if _, err = io.ReadFull(buffered.Reader, prefix); err != nil {
		clientConn.Close()
		return
	}
	tunnelCtx, cancel := context.WithCancel(r.Context())
	defer cancel()
	ctx.Req = r.WithContext(tunnelCtx)
	clientConn = &policyBufferedConn{Conn: clientConn, reader: io.MultiReader(bytes.NewReader(prefix), clientConn), cancel: cancel}
	defer clientConn.Close()
	if !p.trackTunnel(clientConn) {
		return
	}
	defer p.untrackTunnel(clientConn)

	response := "HTTP/1.1 200 Connection Established\r\n\r\n"
	n, err := clientConn.Write([]byte(response))
	if err != nil {
		logResponse("CONNECT", host, 0, "", err)
		logError("发送CONNECT响应失败: %v (已写入 %d 字节)", err, n)
		return
	}

	logResponse("CONNECT", host, http.StatusOK, "Connection Established", nil)
	logDebug("已发送CONNECT响应: %d 字节", n)

	hostname, _, err := net.SplitHostPort(host)
	if err != nil {
		hostname = host
	}

	cert, err := p.getCertForHost(hostname)
	if err != nil {
		logError("生成证书失败 %s: %v", hostname, err)
		return
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		// Keep the client-facing side on HTTP/1.1 so request-level control
		// headers can be inspected and stripped. The target-facing side may
		// still negotiate HTTP/2 and is bridged by serveDefaultTunnel.
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			sni := clientHello.ServerName
			if sni == "" {
				sni = hostname
			}
			return p.getCertForHost(sni)
		},
	}

	tlsConn := tls.Server(clientConn, tlsConfig)
	handshakeCtx, stopHandshake := context.WithTimeout(tunnelCtx, 30*time.Second)
	err = tlsConn.HandshakeContext(handshakeCtx)
	stopHandshake()
	if err != nil {
		logTLS("客户端TLS握手失败: %v", err)
		return
	}

	clientProtocol := tlsConn.ConnectionState().NegotiatedProtocol
	logProtocol("客户端协商的协议: %s", clientProtocol)

	// The client-facing side stays on HTTP/1.1 for interception, while the
	// target-facing connection remains free to negotiate HTTP/2.
	forceProtocol := ""

	// 检查是否通过请求头强制使用 HTTP/1.1（优先级更高）
	if r.Header.Get("X-Mitm-Force-HTTP11") == "true" {
		forceProtocol = "http/1.1"
		logProtocol("通过请求头强制使用 HTTP/1.1")
	}

	// 调用 Delegate.BeforeRequest
	p.delegate.BeforeRequest(ctx)

	// 检查是否被中止
	if ctx.Aborted {
		return
	}

	// 优先使用请求头的代理信息，否则从 Delegate 获取
	var parentProxy *url.URL
	if headerProxy != nil {
		parentProxy = headerProxy
		logDebug("使用请求头指定的代理: %s", proxyURLForLog(parentProxy))
	} else {
		parentProxy, err = p.delegate.ParentProxy(r)
		if err != nil {
			logError("获取代理失败: %v", err)
		}
	}

	// Select connection identity from CONNECT or the first decrypted request.
	ctx.Data["host"] = host
	ctx.Data["forceProtocol"] = forceProtocol
	ctx.Data["requestConfig"] = requestConfig
	ctx.Data["parentProxy"] = parentProxy
	p.serveDefaultTunnel(tlsConn, ctx)
}

func (p *MITMProxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if p.policy != nil {
		p.handlePolicyHTTP(w, r, "")
		return
	}
	ctx := NewContext(r)
	defer p.delegate.Finish(ctx)
	if !p.delegate.Auth(ctx, w) {
		w.Header().Set("Proxy-Authenticate", `Basic realm="Proxy"`)
		w.WriteHeader(http.StatusProxyAuthRequired)
		return
	}
	target := *r.URL
	if target.Scheme == "" {
		target.Scheme = "http"
	}
	if target.Host == "" {
		target.Host = r.Host
	}
	config := parseFingerprintFromHeaders(r.Header)
	parent, err := parseProxyFromHeaders(r.Header)
	if err != nil {
		http.Error(w, "invalid parent proxy", http.StatusBadRequest)
		return
	}
	ctx.Options.HeaderValues = policyHeaders(r.Header)
	ctx.Options.HeaderValues["Host"] = []string{r.Host}
	ctx.Options.VerifyTLS = p.verifyTargetCert
	if target.Scheme == "https" {
		p.applyImitateConfig(ctx.Options, config)
		if config.HTTP2SettingsString != "" {
			ctx.Options.HTTP2SettingsString = config.HTTP2SettingsString
		}
	}
	p.delegate.BeforeRequest(ctx)
	if ctx.Aborted {
		return
	}
	if ctx.Options == nil {
		http.Error(w, "invalid request options", 500)
		return
	}
	if parent == nil {
		parent, err = p.delegate.ParentProxy(r)
		if err != nil {
			p.delegate.ErrorLog(err)
			http.Error(w, "parent proxy selection failed", 502)
			return
		}
	}
	if parent != nil {
		ctx.Options.Proxy = parent.String()
	}
	// A forwarding proxy returns redirects unchanged. The caller controls the
	// next URL, method and credentials; streaming bodies must not be replayed.
	ctx.Options.DisableRedirect = true
	ctx.Options.HeaderValues = policyHeaders(http.Header(ctx.Options.HeaderValues))
	for name := range ctx.Options.HeaderValues {
		if strings.EqualFold(name, "Content-Length") {
			delete(ctx.Options.HeaderValues, name)
		}
	}
	requestCtx, cancel := context.WithCancel(r.Context())
	if ctx.Options.Timeout > 0 {
		requestCtx, cancel = context.WithTimeout(r.Context(), time.Duration(ctx.Options.Timeout)*time.Second)
	}
	defer cancel()
	if deadline, ok := requestCtx.Deadline(); ok {
		_ = http.NewResponseController(w).SetReadDeadline(deadline)
	}
	session, err := fastls.NewSession(*ctx.Options)
	var response fastls.Response
	if err == nil {
		defer session.Close()
		request := fastls.RequestOptions{Body: ctx.Options.Body, DisableRedirect: true}
		if request.Body == "" && r.Body != nil && r.Body != http.NoBody {
			request.BodyReader = r.Body
		}
		response, err = session.DoContext(requestCtx, target.String(), request, r.Method)
	}
	var out *http.Response
	if response.Body != nil {
		defer response.Body.Close()
	}
	if err == nil {
		out = &http.Response{StatusCode: response.Status, Header: http.Header(response.HeaderValues).Clone(), Trailer: response.Trailer, Body: response.Body, Request: r.WithContext(requestCtx)}
	}
	p.delegate.BeforeResponse(ctx, out, err)
	if ctx.Aborted {
		return
	}
	if err != nil {
		http.Error(w, "upstream request failed", http.StatusBadGateway)
		return
	}
	if out == nil || out.Body == nil {
		http.Error(w, "empty upstream response", 502)
		return
	}
	logResponse(r.Method, target.String(), out.StatusCode, http.StatusText(out.StatusCode), nil)
	writeProxyResponse(w, out)
}

func (p *MITMProxy) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p.policy == nil {
			logDebug("收到请求: %s %s (Method: %s, Host: %s, URL: %s)", r.Method, r.URL.Path, r.Method, r.Host, r.URL.String())
		}

		if r.Method == http.MethodConnect {
			if p.policy == nil {
				logDebug("处理CONNECT请求: %s", r.Host)
			}
			p.handleConnect(w, r)
			return
		}

		// 健康检查：只有当请求是直接访问代理服务器本身时才返回状态
		// 判断条件：
		// 1. URL 路径为 "/"
		// 2. GET 方法
		// 3. URL 中没有目标主机（r.URL.Host 为空），表示这是直接访问代理服务器
		//    或者 Host 头等于代理服务器地址
		// 注意：通过代理转发的请求，r.URL 会包含完整的 URL（如 http://localhost:8080/），
		//      所以 r.URL.Host 不为空，不会匹配这个条件
		isProxyHealthCheck := r.URL.Path == "/" && r.Method == http.MethodGet &&
			(r.URL.Host == "" || r.Host == p.listenAddr)

		if isProxyHealthCheck {
			logDebug("收到代理健康检查请求，返回200 OK")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Fastls MITM Proxy is running"))
			return
		}

		p.handleHTTP(w, r)
	})
}

func (p *MITMProxy) Start() error {
	return p.StartContext(context.Background())
}

func (p *MITMProxy) StartContext(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("nil start context")
	}
	listener, err := net.Listen("tcp", p.listenAddr)
	if err != nil {
		return err
	}
	defer listener.Close()

	logrus.Infof("代理服务器启动在 %s", listener.Addr())
	if p.disableConnect {
		logrus.Warnf("CONNECT 隧道请求已禁用")
	}
	server, err := p.prepareServer(listener)
	if err != nil {
		return err
	}
	shutdownResult := make(chan error, 1)
	stopCancellation := context.AfterFunc(ctx, func() { shutdownResult <- p.Stop() })
	err = p.servePrepared(server, listener)
	if stopCancellation() {
		return err
	}
	return errors.Join(err, <-shutdownResult)
}

func (p *MITMProxy) serve(listener net.Listener) error {
	server, err := p.prepareServer(listener)
	if err != nil {
		return err
	}
	return p.servePrepared(server, listener)
}

func (p *MITMProxy) prepareServer(listener net.Listener) (*http.Server, error) {
	server := &http.Server{Addr: listener.Addr().String(), Handler: p.handler()}
	if p.policy != nil {
		server.MaxHeaderBytes = 64 << 10
		server.ReadHeaderTimeout = 30 * time.Second
		server.ReadTimeout = 30 * time.Second
		server.WriteTimeout = 30 * time.Second
		server.IdleTimeout = 30 * time.Second
	}
	p.serverMu.Lock()
	if p.server != nil {
		p.serverMu.Unlock()
		return nil, fmt.Errorf("proxy server is already running")
	}
	p.tunnelMu.Lock()
	p.tunnelClosing = false
	p.tunnelMu.Unlock()
	p.server = server
	p.serverMu.Unlock()
	return server, nil
}

func (p *MITMProxy) servePrepared(server *http.Server, listener net.Listener) error {
	if p.policy != nil && p.policyLimits.connections != nil {
		listener = &policyLimitedListener{Listener: listener, slots: p.policyLimits.connections}
	}
	err := server.Serve(listener)
	p.serverMu.Lock()
	if p.server == server {
		p.server = nil
	}
	p.serverMu.Unlock()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (p *MITMProxy) Shutdown(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("nil shutdown context")
	}
	p.serverMu.Lock()
	server := p.server
	p.serverMu.Unlock()
	p.closeTunnels()
	if server == nil {
		return nil
	}
	err := server.Shutdown(ctx)
	if err != nil && p.policy != nil {
		// The graceful window ended. Close pre-header and ordinary active
		// connections as well; their leases must not outlive policy shutdown.
		_ = server.Close()
	}
	return err
}

func (p *MITMProxy) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return p.Shutdown(ctx)
}

func (p *MITMProxy) trackTunnel(connection net.Conn) bool {
	p.tunnelMu.Lock()
	defer p.tunnelMu.Unlock()
	if p.tunnelClosing {
		_ = connection.Close()
		return false
	}
	if p.tunnels == nil {
		p.tunnels = make(map[net.Conn]struct{})
	}
	p.tunnels[connection] = struct{}{}
	return true
}

func (p *MITMProxy) untrackTunnel(connection net.Conn) {
	p.tunnelMu.Lock()
	delete(p.tunnels, connection)
	p.tunnelMu.Unlock()
}

func (p *MITMProxy) closeTunnels() {
	p.tunnelMu.Lock()
	p.tunnelClosing = true
	connections := make([]net.Conn, 0, len(p.tunnels))
	for connection := range p.tunnels {
		connections = append(connections, connection)
	}
	p.tunnelMu.Unlock()
	for _, connection := range connections {
		_ = connection.Close()
	}
}

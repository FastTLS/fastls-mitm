package main

import (
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
	utls "github.com/refraction-networking/utls"
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

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		logResponse("CONNECT", host, http.StatusInternalServerError, "Internal Server Error", err)
		logDebug("Hijack失败: %v", err)
		if clientConn != nil {
			clientConn.Write([]byte("HTTP/1.1 500 Internal Server Error\r\n\r\n"))
			clientConn.Close()
		}
		return
	}
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
		// still negotiate HTTP/2 and is bridged by handleHTTP1Tunnel.
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
	if err := tlsConn.Handshake(); err != nil {
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

	// Delay dialing until the first decrypted request when no parent proxy was
	// supplied on CONNECT, so request-level proxy headers remain available.
	var targetConn net.Conn
	if parentProxy == nil {
		// 延迟建立连接，在 handleHTTP1Tunnel 中从第一个 HTTPS 请求获取代理信息
		logDebug("CONNECT 阶段未检测到代理信息，延迟建立连接，等待第一个 HTTPS 请求")
		targetConn = nil
	} else {
		// 立即建立连接
		ctxTimeout, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		targetConn, err = p.dialTLSWithFingerprint(ctxTimeout, "tcp", host, forceProtocol, requestConfig, parentProxy)
		cancel()
		if err != nil {
			logError("连接到目标服务器失败 %s: %v", host, err)
			return
		}
		defer targetConn.Close()
	}

	// 检查已建立连接的协议
	targetProtocol := ""
	if targetConn != nil {
		if tlsTargetConn, ok := targetConn.(*tls.Conn); ok {
			targetProtocol = tlsTargetConn.ConnectionState().NegotiatedProtocol
			logProtocol("目标服务器协商的协议: %s", targetProtocol)
		} else if utlsConn, ok := targetConn.(*utls.UConn); ok {
			targetProtocol = utlsConn.ConnectionState().NegotiatedProtocol
			logProtocol("目标服务器协商的协议: %s", targetProtocol)
		}
	}

	// 将连接信息存储到 Context，供 handleHTTP1Tunnel 使用
	ctx.Data["host"] = host
	ctx.Data["forceProtocol"] = forceProtocol
	ctx.Data["requestConfig"] = requestConfig
	ctx.Data["targetConn"] = targetConn
	ctx.Data["parentProxy"] = parentProxy

	// The client side is deliberately HTTP/1.1 so every request can be parsed,
	// delegated and stripped of X-Mitm-* controls. handleHTTP1Tunnel bridges to
	// either HTTP/1.1 or HTTP/2 on the target-facing connection.
	logHTTP1("使用 HTTP/1.x 请求/响应解析和协议交接模式")
	p.handleHTTP1Tunnel(tlsConn, targetConn, hostname, ctx)
}

func (p *MITMProxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if p.policy != nil {
		p.handlePolicyHTTP(w, r, "")
		return
	}
	if r.URL.Host != "" && r.URL.Scheme == "" && r.URL.Path == "" {
		logTunnel("检测到可能的CONNECT请求（URL格式: %s），重定向到handleConnect", r.URL.Host)
		if r.Host != "" {
			p.handleConnect(w, r)
			return
		}
	}

	// 创建上下文
	ctx := NewContext(r)

	targetURL := r.URL.String()
	if r.URL.Scheme == "" {
		if r.URL.Host != "" {
			targetURL = "http://" + r.URL.Host
			if r.URL.Path != "" {
				targetURL += r.URL.Path
			}
			if r.URL.RawQuery != "" {
				targetURL += "?" + r.URL.RawQuery
			}
		} else if r.Host != "" {
			targetURL = "http://" + r.Host + r.URL.Path
			if r.URL.RawQuery != "" {
				targetURL += "?" + r.URL.RawQuery
			}
		}
	}

	// 检查目标 URL 的协议
	targetScheme := ""
	if parsedURL, err := url.Parse(targetURL); err == nil {
		targetScheme = parsedURL.Scheme
	}

	// 解析指纹和代理信息
	requestConfig := parseFingerprintFromHeaders(r.Header)
	headerProxy, err := parseProxyFromHeaders(r.Header)
	if err != nil {
		http.Error(w, "Invalid X-Mitm-Proxy: "+err.Error(), http.StatusBadRequest)
		p.delegate.Finish(ctx)
		return
	}

	fingerprintInfo := formatFingerprintInfo(requestConfig)
	proxyInfo := ""
	if headerProxy != nil {
		proxyInfo = proxyURLForLog(headerProxy)
	}

	logRequest(r.Method, targetURL, fingerprintInfo, proxyInfo)

	// 调用 Delegate.Auth
	if !p.delegate.Auth(ctx, w) {
		logResponse(r.Method, targetURL, http.StatusProxyAuthRequired, "Proxy Authentication Required", nil)
		w.Header().Set("Proxy-Authenticate", "Basic realm=\"Proxy\"")
		w.WriteHeader(http.StatusProxyAuthRequired)
		p.delegate.Finish(ctx)
		return
	}

	req, err := http.NewRequest(r.Method, targetURL, r.Body)
	if err != nil {
		logError("创建请求失败: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		p.delegate.Finish(ctx)
		return
	}

	for key, values := range r.Header {
		if strings.HasPrefix(strings.ToLower(key), "x-mitm-") {
			continue
		}
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	// 初始化上下文 Options
	if ctx.Options == nil {
		ctx.Options = &fastls.Options{
			Timeout: 30,
			Headers: make(map[string]string),
		}
	}

	for key, values := range r.Header {
		if strings.HasPrefix(strings.ToLower(key), "x-mitm-") {
			continue
		}
		if len(values) > 0 {
			ctx.Options.Headers[key] = values[0]
		}
	}

	// 只有 HTTPS 请求才应用指纹配置
	// HTTP 请求不需要 TLS 指纹
	if targetScheme == "https" {
		p.applyImitateConfig(ctx.Options, requestConfig)

		// 优先使用请求头中的 HTTP2SettingsString，如果存在则覆盖
		if requestConfig != nil && requestConfig.HTTP2SettingsString != "" {
			ctx.Options.HTTP2SettingsString = requestConfig.HTTP2SettingsString
			logDebug("使用请求头指定的 HTTP2SettingsString: %s", requestConfig.HTTP2SettingsString)
		}

		// 如果 HTTP2SettingsString 不为空，则解析并覆盖 HTTP2Settings 和 PHeaderOrderKeys
		// 注意：虽然 fastls.NewClient().Do() 会调用 processRequest 来解析，但这里显式解析可以确保一致性
		if ctx.Options.HTTP2SettingsString != "" {
			h2Settings, pHeaderOrderKeys, err := fastls.ParseH2SettingsStringWithPHeaderOrder(ctx.Options.HTTP2SettingsString)
			if err != nil {
				logError("解析 HTTP2SettingsString 失败: %v", err)
			} else {
				// 覆盖 HTTP2Settings
				ctx.Options.HTTP2Settings = fastls.ToHTTP2Settings(h2Settings)
				// 如果解析出 PHeaderOrderKeys，则覆盖
				if len(pHeaderOrderKeys) > 0 {
					ctx.Options.PHeaderOrderKeys = pHeaderOrderKeys
				}
			}
		}
	} else {
		// HTTP 请求：不设置指纹，让 fastls 使用标准库的 http.Client
		// 只设置基本的 User-Agent（如果有）
		if requestConfig != nil {
			// 可以设置 User-Agent，但不设置指纹
			logDebug("HTTP 请求，跳过指纹配置")
		}
	}

	// 如果 HTTP2SettingsString 不为空，则解析并覆盖 HTTP2Settings 和 PHeaderOrderKeys
	// 注意：虽然 fastls.NewClient().Do() 会调用 processRequest 来解析，但这里显式解析可以确保一致性
	if ctx.Options.HTTP2SettingsString != "" {
		h2Settings, pHeaderOrderKeys, err := fastls.ParseH2SettingsStringWithPHeaderOrder(ctx.Options.HTTP2SettingsString)
		if err != nil {
			logError("解析 HTTP2SettingsString 失败: %v", err)
		} else {
			// 覆盖 HTTP2Settings
			ctx.Options.HTTP2Settings = fastls.ToHTTP2Settings(h2Settings)
			// 如果解析出 PHeaderOrderKeys，则覆盖
			if len(pHeaderOrderKeys) > 0 {
				ctx.Options.PHeaderOrderKeys = pHeaderOrderKeys
			}
		}
	}

	// 调用 Delegate.BeforeRequest
	p.delegate.BeforeRequest(ctx)

	// 检查是否中止
	if ctx.Aborted {
		p.delegate.Finish(ctx)
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
			p.delegate.ErrorLog(err)
		}
	}

	// 设置代理到 Options
	if parentProxy != nil {
		ctx.Options.Proxy = parentProxy.String()
	}

	client := fastls.NewClient()
	resp, err := client.DoContext(r.Context(), targetURL, *ctx.Options, r.Method)
	defer resp.Client.CloseIdleConnections()
	if resp.Body != nil {
		defer resp.Body.Close()
	}

	// 将 fastls.Response 转换为 http.Response
	var httpResp *http.Response
	if err == nil {
		httpResp = &http.Response{
			StatusCode: resp.Status,
			Header:     http.Header(resp.HeaderValues).Clone(),
			Body:       resp.Body,
			Trailer:    resp.Trailer,
		}
	}

	// 调用 Delegate.BeforeResponse
	p.delegate.BeforeResponse(ctx, httpResp, err)

	// 检查是否中止
	if ctx.Aborted {
		if err == nil {
			resp.Body.Close()
		}
		p.delegate.Finish(ctx)
		return
	}

	if err != nil {
		logResponse(r.Method, targetURL, http.StatusBadGateway, "Bad Gateway", err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		p.delegate.Finish(ctx)
		return
	}
	// 使用修改后的响应
	if httpResp != nil {
		if len(httpResp.Trailer) > 0 {
			httpResp.Header.Del("Content-Length")
			for name := range httpResp.Trailer {
				httpResp.Header.Add("Trailer", name)
			}
		}
		for key, values := range httpResp.Header {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		w.WriteHeader(httpResp.StatusCode)
		statusText := http.StatusText(httpResp.StatusCode)
		logResponse(r.Method, targetURL, httpResp.StatusCode, statusText, nil)
		if _, copyErr := io.Copy(w, httpResp.Body); copyErr != nil {
			p.delegate.ErrorLog(copyErr)
			p.delegate.Finish(ctx)
			panic(http.ErrAbortHandler)
		}
		for name, values := range httpResp.Trailer {
			w.Header()[name] = append([]string(nil), values...)
		}
	} else {
		for key, value := range resp.Headers {
			w.Header().Set(key, value)
		}
		w.WriteHeader(resp.Status)
		statusText := http.StatusText(resp.Status)
		logResponse(r.Method, targetURL, resp.Status, statusText, nil)
		io.Copy(w, resp.Body)
	}

	// 调用 Delegate.Finish
	p.delegate.Finish(ctx)
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

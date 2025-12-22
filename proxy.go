package main

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
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
	caCert         *x509.Certificate
	caKey          *rsa.PrivateKey
	caCertPEM      []byte
	caKeyPEM       []byte
	server         *http.Server
	certCache      CertCache
	fingerprint    fastls.Fingerprint
	browser        string
	listenAddr     string
	disableConnect bool
	delegate       Delegate
}

// NewMITMProxyOptions MITMProxy 配置选项
type NewMITMProxyOptions struct {
	ListenAddr     string
	Fingerprint    fastls.Fingerprint
	Browser        string
	DisableConnect bool
	Delegate       Delegate
	CertCache      CertCache
}

// NewMITMProxy 创建 MITM 代理服务器
func NewMITMProxy(listenAddr string, fingerprint fastls.Fingerprint, browser string, disableConnect bool) (*MITMProxy, error) {
	return NewMITMProxyWithOptions(NewMITMProxyOptions{
		ListenAddr:     listenAddr,
		Fingerprint:    fingerprint,
		Browser:        browser,
		DisableConnect: disableConnect,
		Delegate:       &DefaultDelegate{},
		CertCache:      NewDefaultCertCache(),
	})
}

// NewMITMProxyWithOptions 使用配置选项创建 MITM 代理服务器
func NewMITMProxyWithOptions(opts NewMITMProxyOptions) (*MITMProxy, error) {
	if opts.Delegate == nil {
		opts.Delegate = &DefaultDelegate{}
	}
	if opts.CertCache == nil {
		opts.CertCache = NewDefaultCertCache()
	}

	proxy := &MITMProxy{
		certCache:      opts.CertCache,
		listenAddr:     opts.ListenAddr,
		fingerprint:    opts.Fingerprint,
		browser:        opts.Browser,
		disableConnect: opts.DisableConnect,
		delegate:       opts.Delegate,
	}

	if err := proxy.generateCA(); err != nil {
		return nil, fmt.Errorf("生成CA证书失败: %v", err)
	}

	return proxy, nil
}

func (p *MITMProxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}

	// 创建上下文
	ctx := NewContext(r)

	// 调用 Delegate.Connect
	p.delegate.Connect(ctx, w)

	// 检查是否中止
	if ctx.Aborted {
		return
	}

	// 解析指纹和代理信息
	requestConfig := parseFingerprintFromHeaders(r.Header)
	headerProxy, _ := parseProxyFromHeaders(r.Header)

	fingerprintInfo := formatFingerprintInfo(requestConfig)
	proxyInfo := ""
	if headerProxy != nil {
		proxyInfo = headerProxy.String()
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

	forceProtocol := ""
	if clientProtocol == "" || clientProtocol == "http/1.1" {
		forceProtocol = "http/1.1"
		logProtocol("强制目标服务器使用协议: %s", forceProtocol)
	}

	// 调用 Delegate.Auth
	if !p.delegate.Auth(ctx, w) {
		logResponse("CONNECT", host, http.StatusProxyAuthRequired, "Proxy Authentication Required", nil)
		w.Header().Set("Proxy-Authenticate", "Basic realm=\"Proxy\"")
		w.WriteHeader(http.StatusProxyAuthRequired)
		return
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
		logDebug("使用请求头指定的代理: %s", parentProxy.String())
	} else {
		parentProxy, err = p.delegate.ParentProxy(r)
		if err != nil {
			logError("获取代理失败: %v", err)
		}
	}

	// CONNECT 阶段无代理信息时延迟建立连接，等待第一个 HTTPS 请求获取代理信息
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
		}
	}

	// 将连接信息存储到 Context，供 handleHTTP1Tunnel 使用
	ctx.Data["host"] = host
	ctx.Data["forceProtocol"] = forceProtocol
	ctx.Data["requestConfig"] = requestConfig
	ctx.Data["targetConn"] = targetConn
	ctx.Data["parentProxy"] = parentProxy

	if targetConn != nil && targetProtocol == "h2" {
		logHTTP2("检测到目标服务器使用 HTTP/2，切换到透明转发模式")
		p.handleTransparentTunnel(tlsConn, targetConn)
		return
	}

	if (clientProtocol == "" || clientProtocol == "http/1.1") &&
		(targetConn == nil || targetProtocol == "" || targetProtocol == "http/1.1") {
		logHTTP1("使用 HTTP/1.x 请求/响应解析模式")
		p.handleHTTP1Tunnel(tlsConn, targetConn, hostname, ctx)
	} else if targetConn != nil {
		logTunnel("使用透明转发模式（支持 HTTP/2）")
		p.handleTransparentTunnel(tlsConn, targetConn)
	} else {
		// 延迟建立连接的情况，只处理 HTTP/1.1
		logHTTP1("使用 HTTP/1.x 请求/响应解析模式（延迟建立连接）")
		p.handleHTTP1Tunnel(tlsConn, nil, hostname, ctx)
	}
}

func (p *MITMProxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
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

	// 解析指纹和代理信息
	requestConfig := parseFingerprintFromHeaders(r.Header)
	headerProxy, _ := parseProxyFromHeaders(r.Header)

	fingerprintInfo := formatFingerprintInfo(requestConfig)
	proxyInfo := ""
	if headerProxy != nil {
		proxyInfo = headerProxy.String()
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

	p.applyImitateConfig(ctx.Options, requestConfig)

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
		logDebug("使用请求头指定的代理: %s", parentProxy.String())
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
	resp, err := client.Do(targetURL, *ctx.Options, r.Method)

	// 将 fastls.Response 转换为 http.Response
	var httpResp *http.Response
	if err == nil {
		httpResp = &http.Response{
			StatusCode: resp.Status,
			Header:     make(http.Header),
			Body:       resp.Body,
		}
		for k, v := range resp.Headers {
			httpResp.Header.Set(k, v)
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
	defer resp.Body.Close()

	// 使用修改后的响应
	if httpResp != nil {
		for key, values := range httpResp.Header {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		w.WriteHeader(httpResp.StatusCode)
		statusText := http.StatusText(httpResp.StatusCode)
		logResponse(r.Method, targetURL, httpResp.StatusCode, statusText, nil)
		io.Copy(w, httpResp.Body)
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

func (p *MITMProxy) Start() error {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logDebug("收到请求: %s %s (Method: %s, Host: %s, URL: %s)", r.Method, r.URL.Path, r.Method, r.Host, r.URL.String())

		if r.Method == http.MethodConnect {
			logDebug("处理CONNECT请求: %s", r.Host)
			p.handleConnect(w, r)
			return
		}

		if r.URL.Path == "/" && r.Method == http.MethodGet {
			logDebug("收到代理测试请求，返回200 OK")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Fastls MITM Proxy is running"))
			return
		}

		p.handleHTTP(w, r)
	})

	p.server = &http.Server{
		Addr:    p.listenAddr,
		Handler: handler,
	}

	logrus.Infof("代理服务器启动在 %s", p.listenAddr)
	if p.disableConnect {
		logrus.Warnf("CONNECT 隧道请求已禁用")
	}

	return p.server.ListenAndServe()
}

func (p *MITMProxy) Stop() error {
	if p.server != nil {
		return p.server.Close()
	}
	return nil
}

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
	"strings"
	"sync"
	"time"

	fastls "github.com/FastTLS/fastls"
	"github.com/sirupsen/logrus"
)

type MITMProxy struct {
	caCert         *x509.Certificate
	caKey          *rsa.PrivateKey
	caCertPEM      []byte
	caKeyPEM       []byte
	server         *http.Server
	certCache      map[string]*tls.Certificate
	certMutex      sync.RWMutex
	fingerprint    fastls.Fingerprint
	browser        string
	listenAddr     string
	disableConnect bool
}

func NewMITMProxy(listenAddr string, fingerprint fastls.Fingerprint, browser string, disableConnect bool) (*MITMProxy, error) {
	proxy := &MITMProxy{
		certCache:      make(map[string]*tls.Certificate),
		listenAddr:     listenAddr,
		fingerprint:    fingerprint,
		browser:        browser,
		disableConnect: disableConnect,
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

	logRequest("CONNECT", host)
	logDebug("收到CONNECT请求: %s -> %s", r.RemoteAddr, host)

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

	requestConfig := parseFingerprintFromHeaders(r.Header)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	targetConn, err := p.dialTLSWithFingerprint(ctx, "tcp", host, forceProtocol, requestConfig)
	if err != nil {
		logError("连接到目标服务器失败 %s: %v", host, err)
		return
	}
	defer targetConn.Close()

	targetProtocol := ""
	if tlsTargetConn, ok := targetConn.(*tls.Conn); ok {
		targetProtocol = tlsTargetConn.ConnectionState().NegotiatedProtocol
		logProtocol("目标服务器协商的协议: %s", targetProtocol)
	}

	if targetProtocol == "h2" {
		logHTTP2("检测到目标服务器使用 HTTP/2，切换到透明转发模式")
		p.handleTransparentTunnel(tlsConn, targetConn)
		return
	}

	if (clientProtocol == "" || clientProtocol == "http/1.1") &&
		(targetProtocol == "" || targetProtocol == "http/1.1") {
		logHTTP1("使用 HTTP/1.x 请求/响应解析模式")
		p.handleHTTP1Tunnel(tlsConn, targetConn, hostname)
	} else {
		logTunnel("使用透明转发模式（支持 HTTP/2）")
		p.handleTransparentTunnel(tlsConn, targetConn)
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

	logRequest(r.Method, targetURL)

	requestConfig := parseFingerprintFromHeaders(r.Header)

	req, err := http.NewRequest(r.Method, targetURL, r.Body)
	if err != nil {
		logError("创建请求失败: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
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

	options := fastls.Options{
		Timeout: 30,
		Headers: make(map[string]string),
	}

	for key, values := range r.Header {
		if strings.HasPrefix(strings.ToLower(key), "x-mitm-") {
			continue
		}
		if len(values) > 0 {
			options.Headers[key] = values[0]
		}
	}

	p.applyImitateConfig(&options, requestConfig)

	client := fastls.NewClient()
	resp, err := client.Do(targetURL, options, r.Method)
	if err != nil {
		logResponse(r.Method, targetURL, http.StatusBadGateway, "Bad Gateway", err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for key, value := range resp.Headers {
		w.Header().Set(key, value)
	}

	w.WriteHeader(resp.Status)
	statusText := http.StatusText(resp.Status)
	logResponse(r.Method, targetURL, resp.Status, statusText, nil)

	io.Copy(w, resp.Body)
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

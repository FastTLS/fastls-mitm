package main

import (
	"bufio"
	"context"
	"crypto/tls"
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
	"golang.org/x/net/http2"
)

func (p *MITMProxy) dialTLSWithFingerprint(ctx context.Context, network, addr string, forceProtocol string, requestConfig *RequestFingerprintConfig, parentProxy *url.URL) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}

	var rawConn net.Conn
	if parentProxy != nil {
		// 通过代理连接
		rawConn, err = p.dialThroughProxy(ctx, network, addr, parentProxy)
		if err != nil {
			return nil, fmt.Errorf("通过代理连接失败: %v", err)
		}
	} else {
		// 直连
		rawConn, err = net.DialTimeout(network, addr, 30*time.Second)
		if err != nil {
			return nil, err
		}
	}

	options := fastls.Options{
		Headers: make(map[string]string),
	}
	fingerprint, userAgent := p.applyImitateConfig(&options, requestConfig)

	if fingerprint == nil || fingerprint.IsEmpty() {
		browserType := p.browser
		if browserType == "" {
			browserType = "firefox"
		}
		logrus.Warnf("警告: 浏览器指纹 (%s) 未设置成功，将使用标准TLS", browserType)
	}

	if fingerprint != nil && !fingerprint.IsEmpty() {
		spec, err := fastls.StringToSpec(fingerprint.Value(), userAgent)
		if err != nil {
			rawConn.Close()
			return nil, fmt.Errorf("创建TLS规范失败: %v", err)
		}

		conn := utls.UClient(rawConn, &utls.Config{
			ServerName:         host,
			OmitEmptyPsk:       true,
			InsecureSkipVerify: true,
		}, utls.HelloCustom)

		if forceProtocol == "http/1.1" {
			for i, ext := range spec.Extensions {
				if _, ok := ext.(*utls.ALPNExtension); ok {
					spec.Extensions[i] = &utls.ALPNExtension{
						AlpnProtocols: []string{"http/1.1"},
					}
					logProtocol("已强制设置 ALPN 为 http/1.1")
					break
				}
			}
		}

		if err := conn.ApplyPreset(spec); err != nil {
			rawConn.Close()
			return nil, fmt.Errorf("应用TLS预设失败: %v", err)
		}

		if err := conn.Handshake(); err != nil {
			conn.Close()
			return nil, fmt.Errorf("TLS握手失败: %v", err)
		}

		return conn, nil
	}

	tlsConfig := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
	}
	if forceProtocol == "http/1.1" {
		tlsConfig.NextProtos = []string{"http/1.1"}
	} else {
		// 默认优先使用 HTTP/2
		tlsConfig.NextProtos = []string{"h2", "http/1.1"}
	}
	conn := tls.Client(rawConn, tlsConfig)

	if err := conn.Handshake(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("TLS握手失败: %v", err)
	}

	return conn, nil
}

func (p *MITMProxy) handleHTTP1Tunnel(clientConn net.Conn, targetConn net.Conn, hostname string, ctx *Context) {
	reader := bufio.NewReader(clientConn)
	firstRequest := true
	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			if err != io.EOF {
				logError("读取客户端请求失败: %v", err)
			}
			return
		}

		requestConfig := parseFingerprintFromHeaders(req.Header)

		// 解析代理信息
		headerProxy, _ := parseProxyFromHeaders(req.Header)
		fingerprintInfo := formatFingerprintInfo(requestConfig)
		proxyInfo := ""
		if headerProxy != nil {
			proxyInfo = headerProxy.String()
		}

		// 记录 HTTPS 请求日志
		targetURL := fmt.Sprintf("https://%s%s", hostname, req.URL.Path)
		if req.URL.RawQuery != "" {
			targetURL += "?" + req.URL.RawQuery
		}
		logRequest(req.Method, targetURL, fingerprintInfo, proxyInfo)

		// 检查是否有已存在的 HTTP/2 连接
		if h2ClientConn, ok := ctx.Data["h2ClientConn"].(*http2.ClientConn); ok && h2ClientConn != nil {
			// 使用现有的 HTTP/2 连接
			modifiedReq := p.modifyRequestHeaders(req, hostname, requestConfig)
			modifiedReq.URL.Scheme = "https"
			modifiedReq.URL.Host = hostname
			if modifiedReq.URL.Path == "" {
				modifiedReq.URL.Path = "/"
			}

			resp, err := h2ClientConn.RoundTrip(modifiedReq)
			if err != nil {
				logError("HTTP/2 请求失败: %v", err)
				delete(ctx.Data, "h2ClientConn")
				return
			}

			if err := p.writeHTTP1Response(clientConn, resp); err != nil {
				logError("写入客户端响应失败: %v", err)
				resp.Body.Close()
				return
			}

			statusText := http.StatusText(resp.StatusCode)
			logResponse(req.Method, targetURL, resp.StatusCode, statusText, nil)

			resp.Body.Close()
			if !strings.EqualFold(req.Header.Get("Connection"), "keep-alive") {
				h2ClientConn.Close()
				delete(ctx.Data, "h2ClientConn")
				return
			}
			continue
		}

		// 第一个请求且连接未建立时建立连接
		if firstRequest && targetConn == nil {
			// 从 Context 获取连接参数
			host := ctx.Data["host"].(string)
			forceProtocol := ctx.Data["forceProtocol"].(string)
			oldRequestConfig := ctx.Data["requestConfig"].(*RequestFingerprintConfig)

			// 优先使用当前请求头的指纹配置，否则使用 Context 中的配置
			fingerprintConfigToUse := requestConfig
			if fingerprintConfigToUse == nil || !fingerprintConfigToUse.Override {
				fingerprintConfigToUse = oldRequestConfig
			}

			// 优先使用请求头的代理信息，否则使用 Context 中的代理信息
			proxyToUse := headerProxy
			if proxyToUse == nil {
				if savedProxy, ok := ctx.Data["parentProxy"].(*url.URL); ok && savedProxy != nil {
					proxyToUse = savedProxy
				}
			}

			if proxyToUse != nil {
				logDebug("使用代理建立连接: %s", proxyToUse.String())
			} else {
				logDebug("直连（未使用代理）")
			}
			ctxTimeout, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			newTargetConn, err := p.dialTLSWithFingerprint(ctxTimeout, "tcp", host, forceProtocol, fingerprintConfigToUse, proxyToUse)
			cancel()
			if err != nil {
				logError("建立连接失败 %s: %v", host, err)
				return
			}
			targetConn = newTargetConn
			ctx.Data["targetConn"] = newTargetConn

			// 检查服务器是否协商了 h2，如果是，使用 HTTP/2 客户端发送请求
			var targetProtocol string
			if tlsTargetConn, ok := targetConn.(*tls.Conn); ok {
				targetProtocol = tlsTargetConn.ConnectionState().NegotiatedProtocol
			} else if utlsConn, ok := targetConn.(*utls.UConn); ok {
				targetProtocol = utlsConn.ConnectionState().NegotiatedProtocol
			}

			if targetProtocol == "h2" {
				// 服务器协商了 h2，使用 HTTP/2 客户端发送请求
				logHTTP2("服务器协商了 HTTP/2，使用 HTTP/2 客户端发送请求")
				modifiedReq := p.modifyRequestHeaders(req, hostname, requestConfig)
				modifiedReq.URL.Scheme = "https"
				modifiedReq.URL.Host = hostname
				if modifiedReq.URL.Path == "" {
					modifiedReq.URL.Path = "/"
				}

				// 创建 HTTP/2 客户端连接
				transport := &http2.Transport{}
				h2ClientConn, err := transport.NewClientConn(targetConn)
				if err != nil {
					logError("创建 HTTP/2 客户端连接失败: %v，降级到 HTTP/1.1", err)
					// 降级到 HTTP/1.1，继续执行后面的 HTTP/1.1 代码
				} else {
					// 使用 HTTP/2 发送请求
					resp, err := h2ClientConn.RoundTrip(modifiedReq)
					if err != nil {
						logError("HTTP/2 请求失败: %v", err)
						h2ClientConn.Close()
						return
					}

					// 将 HTTP/2 响应转换为 HTTP/1.1 格式返回给客户端
					if err := p.writeHTTP1Response(clientConn, resp); err != nil {
						logError("写入客户端响应失败: %v", err)
						resp.Body.Close()
						h2ClientConn.Close()
						return
					}

					// 记录响应日志
					statusText := http.StatusText(resp.StatusCode)
					logResponse(req.Method, targetURL, resp.StatusCode, statusText, nil)

					resp.Body.Close()
					// HTTP/2 连接可以复用，不需要关闭
					if !strings.EqualFold(req.Header.Get("Connection"), "keep-alive") {
						h2ClientConn.Close()
						return
					}
					// 保存 HTTP/2 连接供后续请求使用
					ctx.Data["h2ClientConn"] = h2ClientConn
					continue
				}
			}
		}
		firstRequest = false

		modifiedReq := p.modifyRequestHeaders(req, hostname, requestConfig)

		if err := modifiedReq.Write(targetConn); err != nil {
			logError("写入目标服务器请求失败: %v", err)
			return
		}

		respReader := bufio.NewReader(targetConn)
		peekBytes, err := respReader.Peek(24)
		if err != nil && err != io.EOF {
			logError("Peek 目标服务器响应失败: %v", err)
			return
		}

		isHTTP2 := false
		if len(peekBytes) >= 3 {
			if peekBytes[0] == 0x00 && peekBytes[1] == 0x00 {
				if len(peekBytes) >= 24 {
					preface := string(peekBytes[:24])
					if strings.HasPrefix(preface, "PRI * HTTP/2.0") {
						isHTTP2 = true
					} else if peekBytes[3] >= 0x00 && peekBytes[3] <= 0x0A {
						isHTTP2 = true
					}
				} else {
					isHTTP2 = true
				}
			}
		}

		if isHTTP2 {
			logHTTP2("检测到目标服务器返回 HTTP/2 格式，切换到透明转发模式")
			p.handleTransparentTunnel(clientConn, targetConn)
			return
		}

		resp, err := http.ReadResponse(respReader, modifiedReq)
		if err != nil {
			if err != io.EOF {
				logError("读取目标服务器响应失败: %v", err)
			}
			return
		}

		// 记录响应日志
		statusText := http.StatusText(resp.StatusCode)
		logResponse(req.Method, targetURL, resp.StatusCode, statusText, nil)

		if err := resp.Write(clientConn); err != nil {
			logError("写入客户端响应失败: %v", err)
			return
		}

		if !strings.EqualFold(req.Header.Get("Connection"), "keep-alive") {
			return
		}
	}
}

func (p *MITMProxy) handleTransparentTunnel(clientConn net.Conn, targetConn net.Conn) {
	errChan := make(chan error, 2)
	closeOnce := sync.Once{}

	isNormalCloseError := func(err error) bool {
		if err == nil || err == io.EOF {
			return true
		}
		errStr := err.Error()
		normalErrors := []string{
			"use of closed network connection",
			"broken pipe",
			"connection reset by peer",
			"wsarecv: An existing connection was forcibly closed by the remote host",
			"wsasend: An existing connection was forcibly closed by the remote host",
		}
		for _, normalErr := range normalErrors {
			if strings.Contains(errStr, normalErr) {
				return true
			}
		}
		return false
	}

	closeConnections := func() {
		closeOnce.Do(func() {
			targetConn.Close()
			clientConn.Close()
		})
	}

	go func() {
		defer closeConnections()
		_, err := io.Copy(targetConn, clientConn)
		if err != nil && !isNormalCloseError(err) {
			logError("从客户端到目标服务器转发数据失败: %v", err)
		}
		errChan <- err
	}()

	go func() {
		defer closeConnections()
		_, err := io.Copy(clientConn, targetConn)
		if err != nil && !isNormalCloseError(err) {
			logError("从目标服务器到客户端转发数据失败: %v", err)
		}
		errChan <- err
	}()

	<-errChan
	closeConnections()
}

func (p *MITMProxy) modifyRequestHeaders(req *http.Request, hostname string, requestConfig *RequestFingerprintConfig) *http.Request {
	options := fastls.Options{
		Timeout: 30,
		Headers: make(map[string]string),
	}

	for key, values := range req.Header {
		if strings.HasPrefix(strings.ToLower(key), "x-mitm-") {
			continue
		}
		if len(values) > 0 {
			options.Headers[key] = values[0]
		}
	}

	p.applyImitateConfig(&options, requestConfig)

	newReq := req.Clone(req.Context())
	newReq.Header = make(http.Header)

	for key, value := range options.Headers {
		newReq.Header.Set(key, value)
	}

	if newReq.Header.Get("Host") == "" {
		newReq.Header.Set("Host", req.Host)
	}
	if newReq.Header.Get("Connection") == "" {
		if conn := req.Header.Get("Connection"); conn != "" {
			newReq.Header.Set("Connection", conn)
		}
	}

	newReq.URL.Scheme = "https"
	newReq.URL.Host = hostname
	if newReq.URL.Path == "" {
		newReq.URL.Path = "/"
	}

	if req.Body != nil {
		newReq.Body = req.Body
		newReq.ContentLength = req.ContentLength
	}

	return newReq
}

// writeHTTP1Response 将 HTTP/2 响应转换为 HTTP/1.1 格式并写入客户端连接
func (p *MITMProxy) writeHTTP1Response(clientConn net.Conn, resp *http.Response) error {
	// 写入状态行
	statusLine := fmt.Sprintf("HTTP/1.1 %d %s\r\n", resp.StatusCode, resp.Status)
	if _, err := clientConn.Write([]byte(statusLine)); err != nil {
		return err
	}

	// 写入响应头
	for key, values := range resp.Header {
		for _, value := range values {
			headerLine := fmt.Sprintf("%s: %s\r\n", key, value)
			if _, err := clientConn.Write([]byte(headerLine)); err != nil {
				return err
			}
		}
	}

	// 写入空行分隔头部和正文
	if _, err := clientConn.Write([]byte("\r\n")); err != nil {
		return err
	}

	// 写入响应体
	if resp.Body != nil {
		if _, err := io.Copy(clientConn, resp.Body); err != nil {
			return err
		}
	}

	return nil
}

// dialThroughProxy 通过代理建立连接
func (p *MITMProxy) dialThroughProxy(ctx context.Context, network, addr string, proxyURL *url.URL) (net.Conn, error) {
	// 连接代理服务器
	proxyConn, err := net.DialTimeout("tcp", proxyURL.Host, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("连接代理服务器失败: %v", err)
	}

	// 发送 CONNECT 请求
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", addr, addr)
	if _, err := proxyConn.Write([]byte(connectReq)); err != nil {
		proxyConn.Close()
		return nil, fmt.Errorf("发送 CONNECT 请求失败: %v", err)
	}

	// 读取响应
	reader := bufio.NewReader(proxyConn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		proxyConn.Close()
		return nil, fmt.Errorf("读取代理响应失败: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		proxyConn.Close()
		return nil, fmt.Errorf("代理返回错误状态码: %d %s", resp.StatusCode, resp.Status)
	}

	return proxyConn, nil
}

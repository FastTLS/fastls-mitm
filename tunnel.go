package main

import (
	"bufio"
	"bytes"
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
	fhttp "github.com/FastTLS/fhttp"
	http2 "github.com/FastTLS/fhttp/http2"
	utls "github.com/refraction-networking/utls"
	"github.com/sirupsen/logrus"
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
	// 确保在函数退出时关闭服务端连接
	defer func() {
		// 关闭服务端连接（可能是传入的，也可能是从 Context 获取的）
		if targetConn != nil {
			targetConn.Close()
		} else if savedTargetConn, ok := ctx.Data["targetConn"].(net.Conn); ok && savedTargetConn != nil {
			savedTargetConn.Close()
			delete(ctx.Data, "targetConn")
		}
		// 关闭 HTTP/2 连接（如果存在）
		if h2ClientConn, ok := ctx.Data["h2ClientConn"].(*http2.ClientConn); ok && h2ClientConn != nil {
			h2ClientConn.Close()
			delete(ctx.Data, "h2ClientConn")
		}
	}()

	reader := bufio.NewReader(clientConn)
	firstRequest := true
	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			if err != io.EOF {
				logError("读取客户端请求失败: %v", err)
			}
			// 客户端断开连接，退出循环，defer 会关闭服务端连接
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
			modifiedReq, headerOrder, pHeaderOrder, _ := p.modifyRequestHeaders(req, hostname, requestConfig)
			modifiedReq.URL.Scheme = "https"
			modifiedReq.URL.Host = hostname
			if modifiedReq.URL.Path == "" {
				modifiedReq.URL.Path = "/"
			}

			// 转换为 fhttp.Request
			freq, err := p.convertToFHTTPRequest(modifiedReq, headerOrder, pHeaderOrder)
			if err != nil {
				logError("转换请求失败: %v", err)
				return
			}

			fresp, err := h2ClientConn.RoundTrip(freq)
			if err != nil {
				logError("HTTP/2 请求失败: %v", err)
				delete(ctx.Data, "h2ClientConn")
				return
			}

			// 转换为标准库的 Response
			resp, err := p.convertToHTTPResponse(fresp)
			if err != nil {
				logError("转换响应失败: %v", err)
				fresp.Body.Close()
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
				// 连接建立失败，客户端连接可能已断开，defer 会处理清理
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
				modifiedReq, headerOrder, pHeaderOrder, h2Settings := p.modifyRequestHeaders(req, hostname, requestConfig)
				modifiedReq.URL.Scheme = "https"
				modifiedReq.URL.Host = hostname
				if modifiedReq.URL.Path == "" {
					modifiedReq.URL.Path = "/"
				}

				// 创建 HTTP/2 客户端连接，使用 fhttp/http2 以支持自定义 HTTP2Settings
				transport := &http2.Transport{
					HTTP2Settings: h2Settings,
				}
				h2ClientConn, err := transport.NewClientConn(targetConn)
				if err != nil {
					logError("创建 HTTP/2 客户端连接失败: %v，降级到 HTTP/1.1", err)
					// 降级到 HTTP/1.1，继续执行后面的 HTTP/1.1 代码
				} else {
					// 转换为 fhttp.Request
					freq, err := p.convertToFHTTPRequest(modifiedReq, headerOrder, pHeaderOrder)
					if err != nil {
						logError("转换请求失败: %v", err)
						h2ClientConn.Close()
						// 客户端连接可能已断开，defer 会关闭服务端连接
						return
					}

					// 使用 HTTP/2 发送请求
					fresp, err := h2ClientConn.RoundTrip(freq)
					if err != nil {
						logError("HTTP/2 请求失败: %v", err)
						h2ClientConn.Close()
						// 客户端连接可能已断开，defer 会关闭服务端连接
						return
					}

					// 转换为标准库的 Response
					resp, err := p.convertToHTTPResponse(fresp)
					if err != nil {
						logError("转换响应失败: %v", err)
						fresp.Body.Close()
						h2ClientConn.Close()
						// 客户端连接可能已断开，defer 会关闭服务端连接
						return
					}

					// 将 HTTP/2 响应转换为 HTTP/1.1 格式返回给客户端
					if err := p.writeHTTP1Response(clientConn, resp); err != nil {
						logError("写入客户端响应失败: %v", err)
						resp.Body.Close()
						h2ClientConn.Close()
						// 客户端连接已断开，defer 会关闭服务端连接
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

		modifiedReq, headerOrder, _, _ := p.modifyRequestHeaders(req, hostname, requestConfig)

		if err := p.writeRequestWithHeaderOrder(modifiedReq, targetConn, headerOrder); err != nil {
			logError("写入目标服务器请求失败: %v", err)
			// 客户端连接可能已断开，defer 会关闭服务端连接
			return
		}

		respReader := bufio.NewReader(targetConn)
		peekBytes, err := respReader.Peek(24)
		if err != nil && err != io.EOF {
			logError("Peek 目标服务器响应失败: %v", err)
			// 服务端连接可能已断开，defer 会关闭连接
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
			// 服务端连接可能已断开，defer 会关闭连接
			return
		}

		// 记录响应日志
		statusText := http.StatusText(resp.StatusCode)
		logResponse(req.Method, targetURL, resp.StatusCode, statusText, nil)

		if err := resp.Write(clientConn); err != nil {
			logError("写入客户端响应失败: %v", err)
			// 客户端连接已断开，defer 会关闭服务端连接
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

func (p *MITMProxy) modifyRequestHeaders(req *http.Request, hostname string, requestConfig *RequestFingerprintConfig) (*http.Request, []string, []string, *http2.HTTP2Settings) {
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

	// 优先使用请求头中的 HTTP2SettingsString，如果存在则覆盖
	if requestConfig != nil && requestConfig.HTTP2SettingsString != "" {
		options.HTTP2SettingsString = requestConfig.HTTP2SettingsString
		logDebug("使用请求头指定的 HTTP2SettingsString: %s", requestConfig.HTTP2SettingsString)
	}

	// 如果 HTTP2SettingsString 不为空，则解析并覆盖 HTTP2Settings 和 PHeaderOrderKeys
	if options.HTTP2SettingsString != "" {
		h2Settings, pHeaderOrderKeys, err := fastls.ParseH2SettingsStringWithPHeaderOrder(options.HTTP2SettingsString)
		if err != nil {
			logError("解析 HTTP2SettingsString 失败: %v", err)
		} else {
			// 覆盖 HTTP2Settings
			options.HTTP2Settings = fastls.ToHTTP2Settings(h2Settings)
			// 如果解析出 PHeaderOrderKeys，则覆盖
			if len(pHeaderOrderKeys) > 0 {
				options.PHeaderOrderKeys = pHeaderOrderKeys
			}
		}
	}

	newReq := req.Clone(req.Context())
	newReq.Header = make(http.Header)

	// 保存头部排序信息（不添加到 Header 中，避免 HTTP/2 错误）
	var headerOrder []string
	if options.HeaderOrderKeys != nil {
		headerOrder = options.HeaderOrderKeys
	}

	// 保存伪头部排序信息
	var pHeaderOrder []string
	if options.PHeaderOrderKeys != nil {
		pHeaderOrder = options.PHeaderOrderKeys
	} else {
		// 默认伪头部顺序
		pHeaderOrder = []string{":method", ":authority", ":scheme", ":path"}
	}

	// 保存 HTTP/2 设置
	var h2Settings *http2.HTTP2Settings
	if options.HTTP2Settings != nil {
		h2Settings = options.HTTP2Settings
	}

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

	return newReq, headerOrder, pHeaderOrder, h2Settings
}

// writeRequestWithHeaderOrder 按照 HeaderOrderKeys 的顺序写入 HTTP 请求
func (p *MITMProxy) writeRequestWithHeaderOrder(req *http.Request, w io.Writer, headerOrder []string) error {
	// 写入请求行
	uri := req.URL.Path
	if req.URL.RawQuery != "" {
		uri += "?" + req.URL.RawQuery
	}
	if uri == "" {
		uri = "/"
	}
	requestLine := fmt.Sprintf("%s %s HTTP/1.1\r\n", req.Method, uri)
	if _, err := w.Write([]byte(requestLine)); err != nil {
		return err
	}

	// 创建头部键到值的映射
	headerMap := make(map[string][]string)
	for k, v := range req.Header {
		headerMap[k] = v
	}

	// 按照排序顺序写入头部
	if len(headerOrder) > 0 {
		// 创建已写入标记
		written := make(map[string]bool)

		// 先写入排序中指定的头部
		for _, key := range headerOrder {
			keyLower := strings.ToLower(key)
			for k, values := range headerMap {
				if strings.ToLower(k) == keyLower {
					for _, value := range values {
						headerLine := fmt.Sprintf("%s: %s\r\n", k, value)
						if _, err := w.Write([]byte(headerLine)); err != nil {
							return err
						}
					}
					written[k] = true
					break
				}
			}
		}

		// 写入未在排序中的头部（按字母顺序）
		var remainingKeys []string
		for k := range headerMap {
			if !written[k] {
				remainingKeys = append(remainingKeys, k)
			}
		}
		// 简单排序
		for i := 0; i < len(remainingKeys); i++ {
			for j := i + 1; j < len(remainingKeys); j++ {
				if remainingKeys[i] > remainingKeys[j] {
					remainingKeys[i], remainingKeys[j] = remainingKeys[j], remainingKeys[i]
				}
			}
		}
		for _, k := range remainingKeys {
			for _, value := range headerMap[k] {
				headerLine := fmt.Sprintf("%s: %s\r\n", k, value)
				if _, err := w.Write([]byte(headerLine)); err != nil {
					return err
				}
			}
		}
	} else {
		// 没有排序信息，按字母顺序写入
		var keys []string
		for k := range headerMap {
			keys = append(keys, k)
		}
		// 简单排序
		for i := 0; i < len(keys); i++ {
			for j := i + 1; j < len(keys); j++ {
				if keys[i] > keys[j] {
					keys[i], keys[j] = keys[j], keys[i]
				}
			}
		}
		for _, k := range keys {
			for _, value := range headerMap[k] {
				headerLine := fmt.Sprintf("%s: %s\r\n", k, value)
				if _, err := w.Write([]byte(headerLine)); err != nil {
					return err
				}
			}
		}
	}

	// 写入空行
	if _, err := w.Write([]byte("\r\n")); err != nil {
		return err
	}

	// 写入请求体
	if req.Body != nil {
		if _, err := io.Copy(w, req.Body); err != nil {
			return err
		}
	}

	return nil
}

// convertToFHTTPRequest 将标准库的 http.Request 转换为 fhttp.Request
func (p *MITMProxy) convertToFHTTPRequest(req *http.Request, headerOrder []string, pHeaderOrder []string) (*fhttp.Request, error) {
	freq, err := fhttp.NewRequest(req.Method, req.URL.String(), req.Body)
	if err != nil {
		return nil, err
	}

	// 设置头部排序信息（包括普通头部和伪头部）
	freq.Header = fhttp.Header{}
	if headerOrder != nil {
		freq.Header[fhttp.HeaderOrderKey] = headerOrder
	}
	if pHeaderOrder != nil {
		freq.Header[fhttp.PHeaderOrderKey] = pHeaderOrder
	}

	// 复制请求头
	for key, values := range req.Header {
		for _, value := range values {
			freq.Header.Add(key, value)
		}
	}

	freq.URL = req.URL
	freq.ContentLength = req.ContentLength
	return freq, nil
}

// convertToHTTPResponse 将 fhttp.Response 转换为标准库的 http.Response
func (p *MITMProxy) convertToHTTPResponse(fresp *fhttp.Response) (*http.Response, error) {
	// 读取响应体
	bodyBytes, err := io.ReadAll(fresp.Body)
	if err != nil {
		return nil, err
	}
	fresp.Body.Close()

	// 创建标准库的 Response
	resp := &http.Response{
		Status:     fresp.Status,
		StatusCode: fresp.StatusCode,
		Proto:      fresp.Proto,
		ProtoMajor: fresp.ProtoMajor,
		ProtoMinor: fresp.ProtoMinor,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewReader(bodyBytes)),
	}

	// 复制响应头
	for key, values := range fresp.Header {
		for _, value := range values {
			resp.Header.Add(key, value)
		}
	}

	return resp, nil
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

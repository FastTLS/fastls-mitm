package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	fastls "github.com/FastTLS/fastls"
	"github.com/FastTLS/ftransport"
	utls "github.com/refraction-networking/utls"
	xproxy "golang.org/x/net/proxy"
)

func (p *MITMProxy) dialTLSWithFingerprint(ctx context.Context, network, addr string, forceProtocol string, requestConfig *RequestFingerprintConfig, parentProxy *url.URL) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}

	options := fastls.Options{Headers: make(map[string]string)}
	fingerprint, userAgent := p.applyImitateConfig(&options, requestConfig)
	var spec *utls.ClientHelloSpec
	if options.Profile != nil {
		spec, err = fastls.ProfileToSpec(*options.Profile)
	} else if fingerprint != nil && !fingerprint.IsEmpty() {
		spec, err = fastls.StringToSpec(fingerprint.Value(), userAgent)
	} else {
		return nil, fmt.Errorf("TLS profile is unavailable")
	}
	if err != nil {
		return nil, fmt.Errorf("invalid TLS profile: %w", err)
	}
	if forceProtocol == "http/1.1" {
		found := false
		for i, extension := range spec.Extensions {
			if _, ok := extension.(*utls.ALPNExtension); ok {
				spec.Extensions[i] = &utls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}}
				found = true
			}
		}
		if !found {
			spec.Extensions = append(spec.Extensions, &utls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}})
		}
	}

	var rawConn net.Conn
	if parentProxy != nil {
		// 通过代理连接
		rawConn, err = p.dialThroughProxy(ctx, network, addr, parentProxy)
		if err != nil {
			return nil, fmt.Errorf("通过代理连接失败: %w", err)
		}
	} else {
		// 直连
		rawConn, err = (&net.Dialer{Timeout: 30 * time.Second}).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
	}

	conn := utls.UClient(rawConn, &utls.Config{
		ServerName:             host,
		OmitEmptyPsk:           true,
		InsecureSkipVerify:     !p.verifyTargetCert,
		SessionTicketsDisabled: options.Profile != nil && options.Profile.TLS.SessionPolicy == "disabled",
	}, utls.HelloCustom)

	if err := conn.ApplyPreset(spec); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("应用TLS预设失败: %v", err)
	}

	if err := conn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, fmt.Errorf("TLS握手失败: %w", err)
	}

	return conn, nil
}

func (p *MITMProxy) modifyRequestHeaders(req *http.Request, hostname string, requestConfig *RequestFingerprintConfig) (*http.Request, []string, []string, *ftransport.HTTP2Config) {
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
	var h2Settings *ftransport.HTTP2Config
	if options.HTTP2Settings != nil {
		h2Settings = options.HTTP2Settings
	}

	for key, value := range options.Headers {
		newReq.Header.Set(key, value)
	}
	// Keep repeated caller headers when the profile did not replace them.
	for key, values := range req.Header {
		if !strings.HasPrefix(strings.ToLower(key), "x-mitm-") && len(values) > 0 && newReq.Header.Get(key) == values[0] {
			newReq.Header[key] = append([]string(nil), values...)
		}
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

func withRequestOrder(req *http.Request, headerOrder, pseudoOrder []string) (*http.Request, error) {
	var pseudo []ftransport.PseudoHeader
	if pseudoOrder != nil {
		pseudo = make([]ftransport.PseudoHeader, len(pseudoOrder))
	}
	for i, name := range pseudoOrder {
		pseudo[i] = ftransport.PseudoHeader(name)
	}
	return ftransport.WithRequestOptions(req, ftransport.RequestOptions{
		HeaderOrder:       headerOrder,
		PseudoHeaderOrder: pseudo,
	})
}

func newHTTP2Transport(conn net.Conn, settings *ftransport.HTTP2Config) (*ftransport.Transport, error) {
	config := ftransport.Config{Protocols: []ftransport.Protocol{ftransport.ProtocolHTTP2}}
	if settings != nil {
		config.HTTP2 = *settings
	}
	var mu sync.Mutex
	claimed := false
	config.DialContext = func(ctx context.Context, request ftransport.DialRequest) (ftransport.DialResult, error) {
		mu.Lock()
		defer mu.Unlock()
		if err := ctx.Err(); err != nil {
			return ftransport.DialResult{}, err
		}
		if !request.TLS || claimed {
			return ftransport.DialResult{}, fmt.Errorf("unexpected HTTP/2 connection request")
		}
		claimed = true
		state := &tls.ConnectionState{
			HandshakeComplete:          true,
			NegotiatedProtocol:         "h2",
			NegotiatedProtocolIsMutual: true,
		}
		return ftransport.DialResult{Conn: conn, NegotiatedProtocol: "h2", TLSState: state}, nil
	}
	return ftransport.NewTransport(config)
}

// writeHTTP1Response 将 HTTP/2 响应转换为 HTTP/1.1 格式并写入客户端连接
func (p *MITMProxy) writeHTTP1Response(clientConn net.Conn, resp *http.Response) error {
	// H2 DATA boundaries cannot delimit an H1 body. Use the standard H1
	// encoder so an unknown-length response remains reusable and trailers
	// are emitted only after the source reaches EOF.
	out := *resp
	out.Proto, out.ProtoMajor, out.ProtoMinor = "HTTP/1.1", 1, 1
	out.Header = resp.Header.Clone()
	out.TransferEncoding = nil
	out.Header.Del("Transfer-Encoding")
	hasBody := resp.StatusCode >= 200 && resp.StatusCode != 204 && resp.StatusCode != 304 && (resp.Request == nil || resp.Request.Method != "HEAD")
	if hasBody && (resp.ContentLength < 0 || len(resp.Trailer) > 0) {
		out.ContentLength = -1
		out.Header.Del("Content-Length")
		out.TransferEncoding = []string{"chunked"}
	}
	return out.Write(clientConn)
}

// dialThroughProxy 通过代理建立连接
func (p *MITMProxy) dialThroughProxy(ctx context.Context, network, addr string, proxyURL *url.URL) (net.Conn, error) {
	if ctx == nil {
		return nil, fmt.Errorf("nil proxy dial context")
	}
	if proxyURL == nil || proxyURL.Host == "" {
		return nil, fmt.Errorf("invalid proxy URL")
	}
	if strings.ContainsAny(addr, "\r\n") {
		return nil, fmt.Errorf("invalid target address")
	}
	proxyScheme := strings.ToLower(proxyURL.Scheme)
	if proxyScheme == "socks5" {
		var authentication *xproxy.Auth
		if proxyURL.User != nil {
			password, _ := proxyURL.User.Password()
			authentication = &xproxy.Auth{User: proxyURL.User.Username(), Password: password}
		}
		forward := &net.Dialer{Timeout: 30 * time.Second}
		dialer, err := xproxy.SOCKS5("tcp", proxyURL.Host, authentication, forward)
		if err != nil {
			return nil, fmt.Errorf("创建SOCKS5代理连接失败: %w", err)
		}
		if contextDialer, ok := dialer.(xproxy.ContextDialer); ok {
			connection, err := contextDialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, fmt.Errorf("通过SOCKS5代理连接失败: %w", err)
			}
			return connection, nil
		}
		connection, err := dialer.Dial(network, addr)
		if err != nil {
			return nil, fmt.Errorf("通过SOCKS5代理连接失败: %w", err)
		}
		return connection, nil
	}
	if proxyScheme != "http" && proxyScheme != "https" {
		return nil, fmt.Errorf("unsupported parent proxy scheme %q", proxyURL.Scheme)
	}
	// 连接代理服务器
	dialer := net.Dialer{Timeout: 30 * time.Second}
	proxyConn, err := dialer.DialContext(ctx, "tcp", proxyURL.Host)
	if err != nil {
		return nil, fmt.Errorf("连接代理服务器失败: %w", err)
	}
	handshakeDeadline := time.Now().Add(30 * time.Second)
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(handshakeDeadline) {
		handshakeDeadline = deadline
	}
	_ = proxyConn.SetDeadline(handshakeDeadline)
	deadlineConnection := proxyConn
	stopCancellation := context.AfterFunc(ctx, func() {
		_ = deadlineConnection.SetDeadline(time.Now())
	})
	if proxyScheme == "https" {
		tlsConnection := tls.Client(proxyConn, &tls.Config{
			ServerName: proxyURL.Hostname(),
			RootCAs:    p.proxyTLSRootCAs,
			MinVersion: tls.VersionTLS12,
		})
		if err := tlsConnection.HandshakeContext(ctx); err != nil {
			stopCancellation()
			proxyConn.Close()
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, fmt.Errorf("HTTPS代理TLS握手失败: %w", err)
		}
		proxyConn = tlsConnection
	}

	// 发送 CONNECT 请求
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", addr, addr)
	if proxyURL.User != nil {
		password, _ := proxyURL.User.Password()
		credentials := base64.StdEncoding.EncodeToString([]byte(proxyURL.User.Username() + ":" + password))
		connectReq += "Proxy-Authorization: Basic " + credentials + "\r\n"
	}
	connectReq += "\r\n"
	if _, err := proxyConn.Write([]byte(connectReq)); err != nil {
		stopCancellation()
		proxyConn.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("发送 CONNECT 请求失败: %w", err)
	}

	// 读取响应
	reader := bufio.NewReader(proxyConn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		stopCancellation()
		proxyConn.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("读取代理响应失败: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		stopCancellation()
		proxyConn.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("代理返回错误状态码: %d %s", resp.StatusCode, resp.Status)
	}
	if !stopCancellation() && ctx.Err() != nil {
		proxyConn.Close()
		return nil, ctx.Err()
	}
	_ = proxyConn.SetDeadline(time.Time{})
	if reader.Buffered() > 0 {
		return &bufferedProxyConn{Conn: proxyConn, reader: reader}, nil
	}
	return proxyConn, nil
}

type bufferedProxyConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedProxyConn) Read(buffer []byte) (int, error) {
	return c.reader.Read(buffer)
}

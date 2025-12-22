package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	fastls "github.com/FastTLS/fastls"
	utls "github.com/refraction-networking/utls"
	"github.com/sirupsen/logrus"
)

func (p *MITMProxy) dialTLSWithFingerprint(ctx context.Context, network, addr string, forceProtocol string, requestConfig *RequestFingerprintConfig) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}

	rawConn, err := net.DialTimeout(network, addr, 30*time.Second)
	if err != nil {
		return nil, err
	}

	options := fastls.Options{
		Headers: make(map[string]string),
	}
	fingerprint, userAgent := p.applyImitateConfig(&options, requestConfig)

	if p.fingerprint != nil && !p.fingerprint.IsEmpty() {
		logrus.Infof("使用自定义指纹连接到: %s", host)
	} else {
		browserType := p.browser
		if browserType == "" {
			browserType = "firefox"
		}
		logrus.Infof("使用浏览器指纹 (%s) 连接到: %s, UserAgent: %s", browserType, host, userAgent)
		if fingerprint == nil || fingerprint.IsEmpty() {
			logrus.Warnf("警告: 浏览器指纹 (%s) 未设置成功，将使用标准TLS", browserType)
		} else {
			logrus.Infof("指纹类型: %s, 指纹值: %s", fingerprint.Type(), fingerprint.Value())
		}
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
	}
	conn := tls.Client(rawConn, tlsConfig)

	if err := conn.Handshake(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("TLS握手失败: %v", err)
	}

	return conn, nil
}

func (p *MITMProxy) handleHTTP1Tunnel(clientConn net.Conn, targetConn net.Conn, hostname string) {
	reader := bufio.NewReader(clientConn)
	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			if err != io.EOF {
				logError("读取客户端请求失败: %v", err)
			}
			return
		}

		requestConfig := parseFingerprintFromHeaders(req.Header)
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

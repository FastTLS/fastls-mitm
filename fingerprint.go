package main

import (
	"fmt"
	"net/http"
	"net/url"

	fastls "github.com/FastTLS/fastls"
	"github.com/FastTLS/fastls/imitate"
)

type RequestFingerprintConfig struct {
	Browser  string
	JA3      string
	JA4R     string
	Override bool
}

func parseFingerprintFromHeaders(headers http.Header) *RequestFingerprintConfig {
	config := &RequestFingerprintConfig{}

	if browser := headers.Get("X-Mitm-Browser"); browser != "" {
		config.Browser = browser
		config.Override = true
	}

	if ja3 := headers.Get("X-Mitm-Ja3"); ja3 != "" {
		config.JA3 = ja3
		config.Override = true
	}

	if ja4r := headers.Get("X-Mitm-Ja4r"); ja4r != "" {
		config.JA4R = ja4r
		config.Override = true
	}

	return config
}

// parseProxyFromHeaders 从请求头中解析代理信息
// 支持的请求头: X-Mitm-Proxy
// 格式: http://proxy.example.com:8080 或 http://user:pass@proxy.example.com:8080
func parseProxyFromHeaders(headers http.Header) (*url.URL, error) {
	proxyStr := headers.Get("X-Mitm-Proxy")
	if proxyStr == "" {
		return nil, nil
	}

	proxyURL, err := url.Parse(proxyStr)
	if err != nil {
		return nil, fmt.Errorf("解析代理URL失败: %v", err)
	}

	// 确保是有效的代理URL
	if proxyURL.Scheme != "http" && proxyURL.Scheme != "https" && proxyURL.Scheme != "socks5" {
		return nil, fmt.Errorf("不支持的代理协议: %s (仅支持 http, https, socks5)", proxyURL.Scheme)
	}

	return proxyURL, nil
}

// formatFingerprintInfo 格式化指纹信息用于日志输出
func formatFingerprintInfo(config *RequestFingerprintConfig) string {
	if config == nil {
		return ""
	}

	// 检查是否有任何指纹信息被设置
	if config.JA3 != "" {
		return fmt.Sprintf("JA3:%s", config.JA3)
	}

	if config.JA4R != "" {
		return fmt.Sprintf("JA4R:%s", config.JA4R)
	}

	if config.Browser != "" {
		return fmt.Sprintf("Browser:%s", config.Browser)
	}

	return ""
}

func (p *MITMProxy) applyImitateConfig(options *fastls.Options, requestConfig *RequestFingerprintConfig) (fastls.Fingerprint, string) {
	var fingerprint fastls.Fingerprint
	var userAgent string

	if requestConfig != nil && requestConfig.Override {
		if requestConfig.JA3 != "" {
			fingerprint = fastls.Ja3Fingerprint{
				FingerprintValue: requestConfig.JA3,
			}
			options.Fingerprint = fingerprint
			logDebug("使用请求头指定的JA3指纹: %s", requestConfig.JA3)
			return fingerprint, userAgent
		}

		if requestConfig.JA4R != "" {
			fingerprint = fastls.Ja4Fingerprint{
				FingerprintValue: requestConfig.JA4R,
			}
			options.Fingerprint = fingerprint
			logDebug("使用请求头指定的JA4R指纹: %s", requestConfig.JA4R)
			return fingerprint, userAgent
		}

		if requestConfig.Browser != "" {
			browserType := requestConfig.Browser
			switch browserType {
			case "chrome":
				imitate.Chrome(options)
			case "chrome120":
				imitate.Chrome120(options)
			case "chrome142":
				imitate.Chrome142(options)
			case "chromium":
				imitate.Chromium(options)
			case "edge":
				imitate.Edge(options)
			case "firefox":
				imitate.Firefox(options)
			case "safari":
				imitate.Safari(options)
			case "opera":
				imitate.Opera(options)
			default:
				imitate.Firefox(options)
			}
			fingerprint = options.Fingerprint
			userAgent = options.UserAgent
			if userAgent != "" {
				options.Headers["User-Agent"] = userAgent
			}
			logDebug("使用请求头指定的浏览器指纹: %s", browserType)
			return fingerprint, userAgent
		}
	}

	if p.fingerprint != nil && !p.fingerprint.IsEmpty() {
		options.Fingerprint = p.fingerprint
		fingerprint = p.fingerprint
	} else {
		browserType := p.browser
		if browserType == "" {
			browserType = "firefox"
		}

		switch browserType {
		case "chrome":
			imitate.Chrome(options)
		case "chrome120":
			imitate.Chrome120(options)
		case "chrome142":
			imitate.Chrome142(options)
		case "chromium":
			imitate.Chromium(options)
		case "edge":
			imitate.Edge(options)
		case "firefox":
			imitate.Firefox(options)
		case "safari":
			imitate.Safari(options)
		case "opera":
			imitate.Opera(options)
		default:
			imitate.Firefox(options)
		}

		fingerprint = options.Fingerprint
		userAgent = options.UserAgent

		if userAgent != "" {
			options.Headers["User-Agent"] = userAgent
		}
	}

	return fingerprint, userAgent
}

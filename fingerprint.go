package main

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	fastls "github.com/FastTLS/fastls"
	fastlsimitate "github.com/FastTLS/fastls/imitate"
	generators "github.com/FastTLS/imitate"
)

var fingerprintProvider = generators.New()

type RequestFingerprintConfig struct {
	Browser             string
	JA3                 string
	JA4R                string
	HTTP2SettingsString string
	Override            bool
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

	if http2SettingsString := headers.Get("X-Mitm-H2Settings"); http2SettingsString != "" {
		config.HTTP2SettingsString = http2SettingsString
		config.Override = true
	}

	return config
}

// parseProxyFromHeaders 从请求头解析代理信息
// 支持请求头: X-Mitm-Proxy
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

	// 验证代理协议
	if proxyURL.Scheme != "http" && proxyURL.Scheme != "https" && proxyURL.Scheme != "socks5" {
		return nil, fmt.Errorf("不支持的代理协议: %s (仅支持 http, https, socks5)", proxyURL.Scheme)
	}

	return proxyURL, nil
}

// formatFingerprintInfo 格式化指纹信息用于日志
func formatFingerprintInfo(config *RequestFingerprintConfig) string {
	if config == nil {
		return ""
	}

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
		// 检查是否同时设置了多个指纹类型
		fingerprintCount := 0
		if requestConfig.JA3 != "" {
			fingerprintCount++
		}
		if requestConfig.JA4R != "" {
			fingerprintCount++
		}
		if requestConfig.Browser != "" {
			fingerprintCount++
		}
		if fingerprintCount > 1 {
			logDebug("警告: 同时设置了多个指纹类型，将按优先级使用: JA3 > JA4R > Browser")
		}

		// 优先级: JA3 > JA4R > Browser
		if requestConfig.JA3 != "" {
			fingerprint = fastls.Ja3Fingerprint{
				FingerprintValue: requestConfig.JA3,
			}
			options.Fingerprint = fingerprint
			logDebug("使用请求头指定的 JA3 指纹: %s", requestConfig.JA3)
			return fingerprint, userAgent
		}

		if requestConfig.JA4R != "" {
			fingerprint = fastls.Ja4Fingerprint{
				FingerprintValue: requestConfig.JA4R,
			}
			options.Fingerprint = fingerprint
			logDebug("使用请求头指定的 JA4R 指纹: %s", requestConfig.JA4R)
			return fingerprint, userAgent
		}

		if requestConfig.Browser != "" {
			browserType := requestConfig.Browser
			if err := applyBrowserProfile(options, browserType); err != nil {
				logError("应用浏览器指纹失败: %v", err)
				return nil, ""
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

		if err := applyBrowserProfile(options, browserType); err != nil {
			logError("应用默认浏览器指纹失败: %v", err)
			return nil, ""
		}

		fingerprint = options.Fingerprint
		userAgent = options.UserAgent

		if userAgent != "" {
			options.Headers["User-Agent"] = userAgent
		}
	}

	return fingerprint, userAgent
}

func applyBrowserProfile(options *fastls.Options, browser string) error {
	_, err := fastlsimitate.Use(options, browserSelector(browser), fastlsimitate.WithProvider(fingerprintProvider))
	return err
}

func browserSelector(browser string) string {
	browser = strings.ToLower(strings.TrimSpace(browser))
	selector := "firefox/158/windows"
	if strings.HasPrefix(browser, "firefox") && browser != "firefox" {
		if major, err := strconv.Atoi(strings.TrimPrefix(browser, "firefox")); err == nil &&
			(major >= 151 && major <= 158 || major == 144 || major == 147 || major == 148) {
			selector = fmt.Sprintf("firefox/%d/windows", major)
		}
	}
	if strings.HasPrefix(browser, "chrome") && browser != "chrome" && browser != "chromium" {
		if major, err := strconv.Atoi(strings.TrimPrefix(browser, "chrome")); err == nil &&
			(major == 120 || major == 142 || major >= 150 && major <= 160) {
			selector = fmt.Sprintf("chrome/%d/windows", major)
		}
	}
	if strings.HasPrefix(browser, "edge") && browser != "edge" {
		if major, err := strconv.Atoi(strings.TrimPrefix(browser, "edge")); err == nil && major >= 150 && major <= 160 {
			selector = fmt.Sprintf("edge/%d/windows", major)
		}
	}
	switch browser {
	case "chrome":
		selector = "chrome/160/windows"
	case "chrome120":
		selector = "chrome/120/windows"
	case "chrome142":
		selector = "chrome/142/windows"
	case "chromium":
		selector = "chromium/160/windows"
	case "edge":
		selector = "edge/160/windows"
	case "firefox":
		selector = "firefox/158/windows"
	case "firefox144":
		selector = "firefox/144/windows"
	case "firefox147":
		selector = "firefox/147/windows"
	case "safari":
		selector = "safari/18.7.3/ipados"
	case "opera":
		selector = "opera/145/windows"
	}
	return selector
}

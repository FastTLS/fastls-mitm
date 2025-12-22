package main

import (
	"net/http"

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

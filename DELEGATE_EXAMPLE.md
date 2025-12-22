# Delegate 接口使用示例

参考 [goproxy](https://github.com/ouqiang/goproxy) 的设计，Fastls MITM 代理现在支持事件处理机制。

## 基本用法

```go
package main

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	fastls "github.com/FastTLS/fastls"
)

// EventHandler 实现 Delegate 接口
type EventHandler struct{}

// Connect 收到客户端 CONNECT 请求时调用
func (e *EventHandler) Connect(ctx *Context, rw http.ResponseWriter) {
	// 保存请求ID
	ctx.Data["req_id"] = "uuid-12345"

	// 禁止访问某个域名
	if strings.Contains(ctx.Req.URL.Host, "example.com") {
		rw.WriteHeader(http.StatusForbidden)
		ctx.Aborted = true
		return
	}
}

// Auth 代理身份认证
func (e *EventHandler) Auth(ctx *Context, rw http.ResponseWriter) bool {
	// 检查身份验证
	auth := ctx.Req.Header.Get("Proxy-Authorization")
	if auth == "" {
		rw.Header().Set("Proxy-Authenticate", "Basic realm=\"Proxy\"")
		rw.WriteHeader(http.StatusProxyAuthRequired)
		return false
	}
	return true
}

// BeforeRequest HTTP 请求发送到目标服务器前调用
func (e *EventHandler) BeforeRequest(ctx *Context) {
	// 修改 header
	ctx.Req.Header.Add("X-Request-Id", ctx.Data["req_id"].(string))

	// 设置 X-Forwarded-For
	if clientIP, _, err := net.SplitHostPort(ctx.Req.RemoteAddr); err == nil {
		if prior, ok := ctx.Req.Header["X-Forwarded-For"]; ok {
			clientIP = strings.Join(prior, ", ") + ", " + clientIP
		}
		ctx.Req.Header.Set("X-Forwarded-For", clientIP)
	}

	// 修改 Fastls Options
	if ctx.Options == nil {
		ctx.Options = &fastls.Options{
			Timeout: 30,
			Headers: make(map[string]string),
		}
	}
	ctx.Options.Timeout = 60
	ctx.Options.Headers["X-Custom-Header"] = "custom-value"
}

// BeforeResponse 响应发送到客户端前调用
func (e *EventHandler) BeforeResponse(ctx *Context, resp *http.Response, err error) {
	if err != nil {
		return
	}

	// 修改响应 header
	resp.Header.Set("X-Proxy-Processed", "true")
}

// ParentProxy 返回上级代理 URL
func (e *EventHandler) ParentProxy(req *http.Request) (*url.URL, error) {
	// 可以根据域名选择不同的上级代理
	if strings.Contains(req.Host, "example.com") {
		return url.Parse("http://proxy1.example.com:8080")
	}
	return nil, nil
}

// Finish 本次请求结束时调用
func (e *EventHandler) Finish(ctx *Context) {
	// 记录日志
	reqID := ctx.Data["req_id"]
	_ = reqID // 使用 reqID
}

// ErrorLog 记录错误信息
func (e *EventHandler) ErrorLog(err error) {
	// 记录错误
	_ = err
}

func main() {
	// 创建事件处理器
	handler := &EventHandler{}

	// 创建代理服务器
	proxy, err := NewMITMProxyWithOptions(NewMITMProxyOptions{
		ListenAddr:     ":8888",
		Fingerprint:    nil,
		Browser:        "chrome142",
		DisableConnect: false,
		Delegate:       handler,
		CertCache:      nil, // 使用默认证书缓存
	})
	if err != nil {
		panic(err)
	}

	// 启动代理服务器
	if err := proxy.Start(); err != nil {
		panic(err)
	}
}
```

## 证书缓存接口

```go
// 自定义证书缓存实现
type CustomCertCache struct {
	cache map[string]*tls.Certificate
	mutex sync.RWMutex
}

func (c *CustomCertCache) Set(host string, cert *tls.Certificate) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.cache[host] = cert
}

func (c *CustomCertCache) Get(host string) *tls.Certificate {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.cache[host]
}

// 使用自定义证书缓存
proxy, err := NewMITMProxyWithOptions(NewMITMProxyOptions{
	CertCache: &CustomCertCache{
		cache: make(map[string]*tls.Certificate),
	},
})
```

## 主要改进

参考 [goproxy](https://github.com/ouqiang/goproxy)，Fastls MITM 代理现在支持：

1. **事件处理机制** - 通过 Delegate 接口实现
2. **证书缓存接口** - 可以自定义证书存储方式
3. **上级代理支持** - 通过 ParentProxy 方法实现
4. **请求/响应修改** - 在 BeforeRequest 和 BeforeResponse 中修改
5. **身份认证** - 通过 Auth 方法实现


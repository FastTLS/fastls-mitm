package main

import (
	"net/http"
	"net/url"

	fastls "github.com/FastTLS/fastls"
)

// Delegate 接口定义代理事件处理
// 参考: https://github.com/ouqiang/goproxy
type Delegate interface {
	// Connect 收到客户端 CONNECT 请求时调用
	// 可以在这里禁止访问某些域名、保存请求ID等
	Connect(ctx *Context, rw http.ResponseWriter)

	// Auth 代理身份认证
	// 如果返回 false，代理将拒绝请求
	Auth(ctx *Context, rw http.ResponseWriter) bool

	// BeforeRequest HTTP 请求发送到目标服务器前调用
	// 可以在这里修改 Header、Body、URL 等
	BeforeRequest(ctx *Context)

	// BeforeResponse 响应发送到客户端前调用
	// 可以在这里修改响应 Header、Body、Status Code 等
	BeforeResponse(ctx *Context, resp *http.Response, err error)

	// ParentProxy 返回上级代理 URL
	// 如果返回 nil，则直接连接到目标服务器
	ParentProxy(req *http.Request) (*url.URL, error)

	// Finish 本次请求结束时调用
	// 可以在这里记录日志、清理资源等
	Finish(ctx *Context)

	// ErrorLog 记录错误信息
	ErrorLog(err error)
}

// Context 请求上下文，用于在事件处理函数之间传递数据
type Context struct {
	// Req 原始请求
	Req *http.Request

	// Data 用于存储自定义数据，可以在不同事件处理函数之间共享
	Data map[string]interface{}

	// Aborted 是否中止请求
	Aborted bool

	// Options Fastls 请求选项，可以在 BeforeRequest 中修改
	Options *fastls.Options
}

// NewContext 创建新的上下文
func NewContext(req *http.Request) *Context {
	return &Context{
		Req:     req,
		Data:    make(map[string]interface{}),
		Aborted: false,
		Options: &fastls.Options{
			Timeout: 30,
			Headers: make(map[string]string),
		},
	}
}

// DefaultDelegate 默认的 Delegate 实现，所有方法都是空操作
type DefaultDelegate struct{}

func (d *DefaultDelegate) Connect(ctx *Context, rw http.ResponseWriter) {
	// 默认允许所有 CONNECT 请求
}

func (d *DefaultDelegate) Auth(ctx *Context, rw http.ResponseWriter) bool {
	// 默认不进行身份认证
	return true
}

func (d *DefaultDelegate) BeforeRequest(ctx *Context) {
	// 默认不修改请求
}

func (d *DefaultDelegate) BeforeResponse(ctx *Context, resp *http.Response, err error) {
	// 默认不修改响应
}

func (d *DefaultDelegate) ParentProxy(req *http.Request) (*url.URL, error) {
	// 默认不使用上级代理
	return nil, nil
}

func (d *DefaultDelegate) Finish(ctx *Context) {
	// 默认不做任何操作
}

func (d *DefaultDelegate) ErrorLog(err error) {
	// 默认不记录错误（由日志系统处理）
}

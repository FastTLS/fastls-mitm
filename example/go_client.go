package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

func main() {
	// MITM代理地址（需要先启动mitm_proxy.exe）
	proxyURL := "http://127.0.0.1:8888"

	// 目标URL
	targetURL := "https://tls.peet.ws/api/all"

	fmt.Println("=" + repeat("=", 59))
	fmt.Println("Fastls MITM代理 Golang客户端示例")
	fmt.Println("=" + repeat("=", 59))
	fmt.Println()

	fmt.Printf("通过MITM代理访问目标URL...\n")
	fmt.Printf("代理地址: %s\n", proxyURL)
	fmt.Printf("目标URL: %s\n\n", targetURL)

	// 创建HTTP客户端，配置代理
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL(proxyURL)),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // 忽略SSL证书验证（因为使用MITM证书）
			},
		},
	}

	// 发送请求
	resp, err := client.Get(targetURL)
	if err != nil {
		fmt.Printf("请求失败: %v\n", err)
		fmt.Println("\n请确保MITM代理已启动:")
		fmt.Println("  cd services/fastls-mitm")
		fmt.Println("  ./mitm_proxy.exe -addr :8888 -browser chrome142")
		return
	}
	defer resp.Body.Close()

	// 读取响应
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("读取响应失败: %v\n", err)
		return
	}

	fmt.Printf("状态码: %d\n", resp.StatusCode)
	fmt.Printf("响应头: %v\n", resp.Header)
	fmt.Printf("响应体长度: %d bytes\n", len(body))

	// 显示响应内容（前500字符）
	if len(body) > 500 {
		fmt.Printf("\n响应内容（前500字符）:\n%s\n", string(body[:500]))
	} else {
		fmt.Printf("\n响应内容:\n%s\n", string(body))
	}

	fmt.Println("\n" + "=" + repeat("=", 59))
	fmt.Println("提示: 启动MITM代理时可以使用以下参数:")
	fmt.Println("  -addr :8888          # 监听地址")
	fmt.Println("  -browser chrome142    # 浏览器类型")
	fmt.Println("  -ja3 <指纹>          # 自定义JA3指纹")
	fmt.Println("  -ja4r <指纹>          # 自定义JA4R指纹")
	fmt.Println("=" + repeat("=", 59))
}

func repeat(s string, n int) string {
	result := ""
	for i := 0; i < n; i++ {
		result += s
	}
	return result
}

func mustParseURL(rawURL string) *url.URL {
	u, err := url.Parse(rawURL)
	if err != nil {
		panic(fmt.Sprintf("解析URL失败: %v", err))
	}
	return u
}

package main

import (
	"flag"
	"os"
	"strings"

	fastls "github.com/FastTLS/fastls"
	"github.com/sirupsen/logrus"
)

func main() {
	var (
		listenAddr     string
		browser        string
		ja3            string
		ja4r           string
		caCertPath     string
		caKeyPath      string
		disableConnect bool
		debug          bool
		showVersion    bool
		showHelp       bool
	)

	// 定义完整参数和缩写参数
	flag.StringVar(&listenAddr, "addr", ":8888", "监听地址 (例如: :8888 或 0.0.0.0:8888)")
	flag.StringVar(&listenAddr, "a", ":8888", "监听地址 (addr 的缩写)")

	flag.StringVar(&browser, "browser", "chrome142", "浏览器类型 (chrome, chrome120, chrome142, chromium, edge, firefox, safari, opera)")
	flag.StringVar(&browser, "b", "chrome142", "浏览器类型 (browser 的缩写)")

	flag.StringVar(&ja3, "ja3", "", "自定义JA3指纹字符串 (如果指定，将忽略browser参数)")
	flag.StringVar(&ja3, "j3", "", "自定义JA3指纹字符串 (ja3 的缩写)")

	flag.StringVar(&ja4r, "ja4r", "", "自定义JA4R指纹字符串 (如果指定，将忽略browser参数)")
	flag.StringVar(&ja4r, "j4", "", "自定义JA4R指纹字符串 (ja4r 的缩写)")

	flag.StringVar(&caCertPath, "ca-cert", "mitm-ca-cert.pem", "CA证书文件路径")
	flag.StringVar(&caCertPath, "c", "mitm-ca-cert.pem", "CA证书文件路径 (ca-cert 的缩写)")

	flag.StringVar(&caKeyPath, "ca-key", "mitm-ca-key.pem", "CA私钥文件路径")
	flag.StringVar(&caKeyPath, "k", "mitm-ca-key.pem", "CA私钥文件路径 (ca-key 的缩写)")

	flag.BoolVar(&disableConnect, "disable-connect", false, "禁用 CONNECT 隧道请求，只支持 HTTP 代理方式")
	flag.BoolVar(&disableConnect, "dc", false, "禁用 CONNECT 隧道请求 (disable-connect 的缩写)")

	flag.BoolVar(&debug, "debug", false, "启用 Debug 模式，显示详细的调试日志")
	flag.BoolVar(&debug, "d", false, "启用 Debug 模式 (debug 的缩写)")

	flag.BoolVar(&showVersion, "version", false, "显示版本信息并退出")
	flag.BoolVar(&showVersion, "v", false, "显示版本信息并退出 (version 的缩写)")

	flag.BoolVar(&showHelp, "help", false, "显示帮助信息并退出")
	flag.BoolVar(&showHelp, "h", false, "显示帮助信息并退出 (help 的缩写)")

	flag.Usage = func() {
		printHelp()
	}

	flag.Parse()

	if showHelp || len(os.Args) > 1 && (os.Args[1] == "-h" || os.Args[1] == "--help") {
		printHelp()
		os.Exit(0)
	}

	if showVersion {
		printVersion()
		os.Exit(0)
	}

	setupLogging(debug)

	var fingerprint fastls.Fingerprint = nil
	browserType := ""

	if ja3 != "" {
		fingerprint = fastls.Ja3Fingerprint{
			FingerprintValue: ja3,
		}
	} else if ja4r != "" {
		fingerprint = fastls.Ja4Fingerprint{
			FingerprintValue: ja4r,
		}
	} else {
		browserType = browser
	}

	proxy, err := NewMITMProxy(listenAddr, fingerprint, browserType, disableConnect)
	if err != nil {
		logrus.Fatalf("创建代理服务器失败: %v", err)
	}

	if debug {
		logrus.Info("=" + strings.Repeat("=", 60))
		logrus.Info("中间人代理服务器配置:")
		logrus.Infof("  监听地址: %s", listenAddr)
		logrus.Infof("  CA证书: %s", caCertPath)
		logrus.Infof("  CA私钥: %s", caKeyPath)
		logrus.Infof("  日志级别: Debug")
		logrus.Info("=" + strings.Repeat("=", 60))
	}

	if err := proxy.Start(); err != nil {
		logrus.Fatalf("代理服务器启动失败: %v", err)
	}
}

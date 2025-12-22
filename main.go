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
		listenAddr     = flag.String("addr", ":8888", "监听地址 (例如: :8888 或 0.0.0.0:8888)")
		browser        = flag.String("browser", "chrome142", "浏览器类型 (chrome, chrome120, chrome142, chromium, edge, firefox, safari, opera)")
		ja3            = flag.String("ja3", "", "自定义JA3指纹字符串 (如果指定，将忽略browser参数)")
		ja4r           = flag.String("ja4r", "", "自定义JA4R指纹字符串 (如果指定，将忽略browser参数)")
		caCertPath     = flag.String("ca-cert", "mitm-ca-cert.pem", "CA证书文件路径")
		caKeyPath      = flag.String("ca-key", "mitm-ca-key.pem", "CA私钥文件路径")
		disableConnect = flag.Bool("disable-connect", false, "禁用 CONNECT 隧道请求，只支持 HTTP 代理方式")
		debug          = flag.Bool("debug", false, "启用 Debug 模式，显示详细的调试日志")
		showVersion    = flag.Bool("version", false, "显示版本信息并退出")
		showHelp       = flag.Bool("help", false, "显示帮助信息并退出")
	)

	flag.Usage = func() {
		printHelp()
	}

	flag.Parse()

	if *showHelp || len(os.Args) > 1 && (os.Args[1] == "-h" || os.Args[1] == "--help") {
		printHelp()
		os.Exit(0)
	}

	if *showVersion {
		printVersion()
		os.Exit(0)
	}

	setupLogging(*debug)

	var fingerprint fastls.Fingerprint = nil
	browserType := ""

	if *ja3 != "" {
		fingerprint = fastls.Ja3Fingerprint{
			FingerprintValue: *ja3,
		}
	} else if *ja4r != "" {
		fingerprint = fastls.Ja4Fingerprint{
			FingerprintValue: *ja4r,
		}
	} else {
		browserType = *browser
	}

	proxy, err := NewMITMProxy(*listenAddr, fingerprint, browserType, *disableConnect)
	if err != nil {
		logrus.Fatalf("创建代理服务器失败: %v", err)
	}

	if *debug {
		logrus.Info("=" + strings.Repeat("=", 60))
		logrus.Info("中间人代理服务器配置:")
		logrus.Infof("  监听地址: %s", *listenAddr)
		logrus.Infof("  CA证书: %s", *caCertPath)
		logrus.Infof("  CA私钥: %s", *caKeyPath)
		logrus.Infof("  日志级别: Debug")
		logrus.Info("=" + strings.Repeat("=", 60))
	}

	if err := proxy.Start(); err != nil {
		logrus.Fatalf("代理服务器启动失败: %v", err)
	}
}

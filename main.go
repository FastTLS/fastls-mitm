package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	fastls "github.com/FastTLS/fastls"
	"github.com/sirupsen/logrus"
)

func main() {
	var (
		listenAddr       string
		browser          string
		ja3              string
		ja4r             string
		caCertPath       string
		caKeyPath        string
		disableConnect   bool
		verifyTargetCert bool
		debug            bool
		showVersion      bool
		showHelp         bool
		policyFile       string
		policyMaximum    int64
		policyInflight   int
		policyTunnels    int
		policyTunnelAge  time.Duration
	)

	// 定义完整参数和缩写参数
	flag.StringVar(&listenAddr, "addr", ":8888", "监听地址 (例如: :8888 或 0.0.0.0:8888)")
	flag.StringVar(&listenAddr, "a", ":8888", "监听地址 (addr 的缩写)")
	flag.StringVar(&policyFile, "address-policy", "", "Trusted address policy JSON file; unsupported cores refuse startup")
	flag.Int64Var(&policyMaximum, "policy-max-request-bytes", 4<<20, "Buffered request limit in policy mode (1..64 MiB); requires address-policy")
	flag.IntVar(&policyInflight, "policy-max-inflight", 0, "Maximum active policy HTTP requests; 0 is unlimited; requires address-policy")
	flag.IntVar(&policyTunnels, "policy-max-tunnels", 0, "Maximum admitted policy CONNECT tunnels; 0 is unlimited; requires address-policy")
	flag.DurationVar(&policyTunnelAge, "policy-tunnel-max-age", 0, "Maximum policy tunnel lifetime (0..24h); 0 disables; requires address-policy")

	flag.StringVar(&browser, "browser", "chrome142", "浏览器类型 (chrome/chrome160, chrome150..160, edge/edge160, edge150..160, firefox/firefox158, firefox151..158, safari, opera)")
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

	flag.BoolVar(&verifyTargetCert, "verify-cert", false, "验证目标服务器的 SSL 证书（默认不验证）")
	flag.BoolVar(&verifyTargetCert, "vc", false, "验证目标服务器的 SSL 证书 (verify-cert 的缩写)")

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
	if policyFile == "" {
		explicitMaximum := false
		flag.Visit(func(f *flag.Flag) {
			if strings.HasPrefix(f.Name, "policy-") {
				explicitMaximum = true
			}
		})
		if explicitMaximum {
			logrus.Fatal("policy resource flags require address-policy")
		}
		policyMaximum = 0
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

	proxy, err := NewMITMProxyWithOptions(NewMITMProxyOptions{
		AddressPolicyFile:     policyFile,
		PolicyMaxRequestBytes: policyMaximum,
		PolicyMaxInflight:     policyInflight,
		PolicyMaxTunnels:      policyTunnels,
		PolicyTunnelMaxAge:    policyTunnelAge,
		ListenAddr:            listenAddr,
		Fingerprint:           fingerprint,
		Browser:               browserType,
		DisableConnect:        disableConnect,
		VerifyTargetCert:      verifyTargetCert,
		Delegate:              &DefaultDelegate{},
		CertCache:             NewDefaultCertCache(),
		CACertPath:            caCertPath,
		CAKeyPath:             caKeyPath,
	})
	if err != nil {
		logrus.Fatalf("创建代理服务器失败: %v", err)
	}

	if debug {
		logrus.Info("=" + strings.Repeat("=", 60))
		logrus.Info("中间人代理服务器配置:")
		logrus.Infof("  监听地址: %s", listenAddr)
		logrus.Infof("  CA证书: %s", caCertPath)
		logrus.Infof("  CA私钥: %s", caKeyPath)
		if verifyTargetCert {
			logrus.Infof("  目标服务器证书验证: 启用")
		} else {
			logrus.Infof("  目标服务器证书验证: 禁用（默认）")
		}
		logrus.Infof("  日志级别: Debug")
		logrus.Info("=" + strings.Repeat("=", 60))
	}

	shutdownContext, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	if err := proxy.StartContext(shutdownContext); err != nil {
		logrus.Fatalf("代理服务器启动失败: %v", err)
	}
	if shutdownContext.Err() != nil {
		logrus.Info("代理服务器已安全停止")
	}
}

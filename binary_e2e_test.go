package main

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestMITMBinaryHTTPAndHTTPSProxy(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.URL.Path)
	})
	httpTarget := httptest.NewServer(handler)
	defer httpTarget.Close()
	httpsTarget := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.Proto+"|"+r.URL.Path)
	}))
	httpsTarget.EnableHTTP2 = true
	httpsTarget.StartTLS()
	defer httpsTarget.Close()

	binary := buildMITMTestBinary(t)
	address := reserveMITMLoopbackAddress(t)
	caDirectory := t.TempDir()
	caCertPath := filepath.Join(caDirectory, "ca-cert.pem")
	caKeyPath := filepath.Join(caDirectory, "ca-key.pem")
	process := startMITMTestBinary(t, binary,
		"-addr", address,
		"-browser", "firefox",
		"-ca-cert", caCertPath,
		"-ca-key", caKeyPath,
	)
	waitForMITMHTTP(t, "http://"+address+"/", process)

	proxyURL, err := url.Parse("http://" + address)
	if err != nil {
		t.Fatal(err)
	}
	httpClient := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	assertMITMBinaryResponse(t, httpClient, httpTarget.URL+"/plain", "/plain", process)

	caPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("generated MITM CA could not be parsed")
	}
	httpsClient := &http.Client{Transport: &http.Transport{
		Proxy:             http.ProxyURL(proxyURL),
		TLSClientConfig:   &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2: true,
	}}
	assertMITMBinaryResponse(t, httpsClient, httpsTarget.URL+"/secure", "HTTP/2.0|/secure", process)
}

func assertMITMBinaryResponse(t testing.TB, client *http.Client, endpoint, expected string, process *mitmTestProcess) {
	t.Helper()
	response, err := client.Get(endpoint)
	if err != nil {
		t.Fatalf("proxy request failed: %v\n%s", err, process.logs())
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(body) != expected {
		t.Fatalf("proxy response: status=%d body=%q", response.StatusCode, body)
	}
}

type mitmTestProcess struct {
	command *exec.Cmd
	logPath string
	logFile *os.File
	stop    sync.Once
}

func buildMITMTestBinary(t testing.TB) string {
	t.Helper()
	name := "fastls-mitm"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	path := filepath.Join(t.TempDir(), name)
	command := exec.Command("go", "build", "-trimpath", "-o", path, ".")
	command.Env = append(os.Environ(), "GOWORK=off")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build test binary: %v\n%s", err, output)
	}
	return path
}

func reserveMITMLoopbackAddress(t testing.TB) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func startMITMTestBinary(t testing.TB, binary string, arguments ...string) *mitmTestProcess {
	t.Helper()
	logPath := filepath.Join(t.TempDir(), "process.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(binary, arguments...)
	command.Stdout = logFile
	command.Stderr = logFile
	if err := command.Start(); err != nil {
		logFile.Close()
		t.Fatal(err)
	}
	process := &mitmTestProcess{command: command, logPath: logPath, logFile: logFile}
	t.Cleanup(process.close)
	return process
}

func (p *mitmTestProcess) close() {
	p.stop.Do(func() {
		if p.command.Process != nil {
			_ = p.command.Process.Kill()
			_, _ = p.command.Process.Wait()
		}
		_ = p.logFile.Close()
	})
}

func (p *mitmTestProcess) logs() string {
	p.close()
	data, _ := os.ReadFile(p.logPath)
	return string(data)
}

func waitForMITMHTTP(t testing.TB, endpoint string, process *mitmTestProcess) {
	t.Helper()
	var lastErr error
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		response, err := http.Get(endpoint)
		if err == nil {
			response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
		}
		lastErr = err
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("MITM service did not become ready: %v\n%s", lastErr, process.logs())
}

# MITM 客户端接入

仅用于授权测试。先按 [主指南](../README.md) 启动代理，显式限定环回地址并开启目标证书校验：

```sh
go run . -addr 127.0.0.1:8888 -browser chrome -verify-cert
```

从仓库根运行，生成的 mitm-ca-cert.pem 是客户端需要信任的 CA；mitm-ca-key.pem 是私钥，只留在代理端。本目录历史独立脚本仅供接口追溯，运行前须复核其证书处理；优先使用下面保持证书验证的示例。

## curl

```sh
curl --proxy http://127.0.0.1:8888 --cacert mitm-ca-cert.pem https://example.com/
```

## Python

安装 requests，在包含 CA 文件的目录运行：

```python
import requests

with requests.Session() as session:
    session.proxies = {"http": "http://127.0.0.1:8888", "https": "http://127.0.0.1:8888"}
    session.verify = "mitm-ca-cert.pem"
    response = session.get("https://example.com/", timeout=30)
    response.raise_for_status()
    print(response.text)
```

## Go

客户端使用标准 net/http，与代理的 Fastls 出站配置无关：

```go
package main

import (
    "crypto/tls"
    "crypto/x509"
    "fmt"
    "io"
    "net/http"
    "net/url"
    "os"
    "time"
)

func main() {
    if err := run(); err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
}

func run() error {
    pem, err := os.ReadFile("mitm-ca-cert.pem")
    if err != nil { return err }
    roots := x509.NewCertPool()
    if !roots.AppendCertsFromPEM(pem) { return fmt.Errorf("invalid proxy CA") }
    proxy, err := url.Parse("http://127.0.0.1:8888")
    if err != nil { return err }
    transport := &http.Transport{
        Proxy: http.ProxyURL(proxy),
        TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
    }
    defer transport.CloseIdleConnections()
    client := &http.Client{Transport: transport, Timeout: 30*time.Second}
    response, err := client.Get("https://example.com/")
    if err != nil { return err }
    defer response.Body.Close()
    _, err = io.Copy(os.Stdout, response.Body)
    return err
}
```

## Node.js

Node 的 https.request 没有通用 proxy 配置字段。安装 `https-proxy-agent`，保存为 client.mjs 后运行；CA 通过目标 TLS 选项传入：

```js
import https from 'node:https';
import { readFileSync } from 'node:fs';
import { HttpsProxyAgent } from 'https-proxy-agent';

const agent = new HttpsProxyAgent('http://127.0.0.1:8888');
const request = https.get('https://example.com/', {
  agent,
  ca: readFileSync('mitm-ca-cert.pem'),
}, response => {
  console.log(response.statusCode);
  response.pipe(process.stdout);
  response.on('end', () => agent.destroy());
  response.on('error', error => { console.error(error); agent.destroy(); process.exitCode = 1; });
});
request.setTimeout(30_000, () => request.destroy(new Error('request timed out')));
request.on('error', error => { console.error(error); agent.destroy(); process.exitCode = 1; });
```

不要使用 verify=False、InsecureSkipVerify 或 rejectUnauthorized=false 代替信任 CA。请求级指纹配置、上级代理及委托模式见 [MITM_PROXY.md](../MITM_PROXY.md) 和 [DELEGATE_EXAMPLE.md](../DELEGATE_EXAMPLE.md)。这些配置由可信调用方控制；浏览器选择器以安装版本帮助为准，不表示完整浏览器一致性。

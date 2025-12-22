# MITM代理客户端示例

本目录包含使用 Fastls MITM代理的客户端示例，支持 Python、Golang 和 Node.js。

## 启动MITM代理

```bash
cd services/fastls-mitm
go run mitm_proxy.go -addr :8888 -browser chrome142
# 或
./mitm_proxy.exe -addr :8888 -browser chrome142
```

代理默认运行在 `http://127.0.0.1:8888`

## 安装CA证书

使用MITM代理前，需要安装生成的CA证书：

1. 启动代理后，会在当前目录生成 `mitm-ca-cert.pem`
2. 将证书添加到系统信任的根证书颁发机构
3. 或者使用 `verify=False` 忽略证书验证（仅用于测试）

## Python 客户端

### 安装依赖

```bash
pip install requests
```

### 运行示例

```bash
python python_client.py
```

### 使用示例

```python
import requests

# 通过MITM代理发送请求
response = requests.get(
    "https://example.com",
    proxies={
        "http": "http://127.0.0.1:8888",
        "https": "http://127.0.0.1:8888"
    },
    verify=False  # 忽略SSL证书验证
)
print(response.text)
```

## Golang 客户端

### 运行示例

```bash
go run go_client.go
```

### 使用示例

```go
package main

import (
    "crypto/tls"
    "net/http"
)

func main() {
    client := &http.Client{
        Transport: &http.Transport{
            Proxy: http.ProxyURL("http://127.0.0.1:8888"),
            TLSClientConfig: &tls.Config{
                InsecureSkipVerify: true,
            },
        },
    }
    
    resp, _ := client.Get("https://example.com")
    // 处理响应...
}
```

## Node.js 客户端

### 运行示例

```bash
node nodejs_client.js
```

### 使用axios（推荐）

```bash
npm install axios
```

```javascript
const axios = require('axios');
const https = require('https');

axios.get('https://example.com', {
    proxy: {
        host: '127.0.0.1',
        port: 8888
    },
    httpsAgent: new https.Agent({
        rejectUnauthorized: false
    })
})
.then(response => {
    console.log(response.data);
});
```

## 代理参数

启动MITM代理时可以使用的参数：

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-addr` | 监听地址 | `:8888` |
| `-browser` | 浏览器类型 | `chrome142` |
| `-ja3` | 自定义JA3指纹 | 空 |
| `-ja4r` | 自定义JA4R指纹 | 空 |
| `-ca-cert` | CA证书路径 | `mitm-ca-cert.pem` |
| `-ca-key` | CA私钥路径 | `mitm-ca-key.pem` |

## 支持的浏览器类型

- `chrome` - Chrome浏览器
- `chrome120` - Chrome 120版本
- `chrome142` - Chrome 142版本
- `chromium` - Chromium浏览器
- `edge` - Microsoft Edge浏览器
- `firefox` - Firefox浏览器
- `safari` - Safari浏览器
- `opera` - Opera浏览器

## 注意事项

1. **证书安装**: 使用HTTPS时，需要安装MITM代理生成的CA证书
2. **证书验证**: 生产环境应正确安装证书，测试环境可以使用 `verify=False`
3. **代理地址**: 确保代理地址和端口与启动参数一致
4. **防火墙**: 确保防火墙允许代理端口通信
5. **TLS指纹**: 代理会根据启动参数设置TLS指纹，影响与目标服务器的连接

## 使用场景

- 网络流量分析
- TLS指纹测试
- 中间人攻击测试（合法授权）
- 调试HTTPS通信
- 安全研究

## 安全提示

⚠️ **警告**: MITM代理可以拦截和修改HTTPS流量，仅应在合法授权的环境中使用。


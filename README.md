# Fastls MITM 代理服务器

中间人代理服务器，支持 TLS 指纹伪造。

## 什么是 CONNECT 请求？

CONNECT 是 HTTP/1.1 协议中定义的一种特殊方法，用于通过代理服务器建立**隧道连接**。

### 为什么需要 CONNECT？

当客户端（浏览器、curl、Python requests 等）需要通过 HTTP 代理访问 **HTTPS 网站**时，会使用 CONNECT 方法：

1. **HTTPS 需要端到端加密**: HTTPS 要求客户端和服务器之间直接建立 TLS 连接，中间不能有代理查看或修改内容
2. **代理无法解析 HTTPS**: 由于 HTTPS 流量是加密的，代理服务器无法像处理 HTTP 那样解析请求头和内容
3. **隧道模式**: CONNECT 方法让代理服务器建立一个"隧道"，只是转发原始字节流，不解析内容

### CONNECT 请求的工作流程

```
客户端                   代理服务器                   目标服务器
   |                         |                            |
   |  CONNECT example.com:443 HTTP/1.1  |                |
   |------------------------>|                            |
   |                         |                            |
   |  HTTP/1.1 200 Connection Established |               |
   |<------------------------|                            |
   |                         |                            |
   |  [TLS 握手开始]          |                            |
   |------------------------>|                            |
   |                         |  [建立 TCP 连接]            |
   |                         |--------------------------->|
   |                         |  [TLS 握手]                |
   |                         |<-------------------------->|
   |  [TLS 握手完成]          |                            |
   |<------------------------|                            |
   |                         |                            |
   |  [加密的 HTTPS 数据]      |  [转发加密数据]            |
   |<=======================>|<==========================>|
```

### 两种请求类型的区别

| 请求类型 | 协议 | 代理处理方式 | 示例 |
|---------|------|------------|------|
| **普通 HTTP 请求** | HTTP | 代理解析请求，转发到目标服务器 | `GET http://example.com/page` |
| **CONNECT 请求** | HTTPS | 代理建立隧道，直接转发字节流 | `CONNECT example.com:443` |

### 在日志中看到的 CONNECT 请求

当你使用 curl 或浏览器访问 HTTPS 网站时，会看到类似这样的日志：

```
2025/12/16 15:14:53 收到请求: CONNECT  (Method: CONNECT, Host: tls.peet.ws:443, URL: //tls.peet.ws:443)
2025/12/16 15:14:53 处理CONNECT请求: tls.peet.ws:443
2025/12/16 15:14:53 收到CONNECT请求: 127.0.0.1:49975 -> tls.peet.ws:443
2025/12/16 15:14:53 已发送CONNECT响应: 39 字节
```

这是正常的！表示：
1. 客户端（curl）向代理发送了 CONNECT 请求，要求连接到 `tls.peet.ws:443`
2. 代理服务器响应 `200 Connection Established`，表示隧道已建立
3. 之后代理会建立两个 TLS 连接（见下方说明）

### ⚠️ 重要：MITM 代理确实在"解析后转发"，指纹在 TLS 握手时应用！

**关键理解**：MITM 代理不是简单的转发，而是**解密后重新加密转发**，指纹在**代理与目标服务器建立 TLS 连接时**应用！

#### 普通代理 vs MITM 代理

**普通代理**（透明代理，只转发）：
```
客户端 → 代理: CONNECT example.com:443
代理 → 客户端: 200 Connection Established
[之后代理只是转发加密字节流，无法查看内容，无法应用指纹]
```

**MITM 代理**（中间人代理，解析后转发）：
```
客户端 → 代理: CONNECT example.com:443
代理 → 客户端: 200 Connection Established

[阶段1: 代理与客户端建立 TLS 连接]
客户端 ←→ 代理: TLS 握手（使用伪造证书）
         ↓
     [代理解密客户端发送的数据，可以看到内容！]

[阶段2: 代理与目标服务器建立 TLS 连接 - 这里应用指纹！]
代理 ←→ 目标服务器: TLS 握手（使用指纹！）
         ↓
     [目标服务器看到的是指定的浏览器指纹，如 Chrome 142]

[阶段3: 双向转发，代理可以查看和修改内容]
客户端 ←→ 代理 ←→ 目标服务器
（解密）  （可查看/修改）  （使用指纹）
```

#### 指纹在哪里应用？

**关键点**：指纹是在**代理与目标服务器建立 TLS 连接时**应用的，不是在转发 HTTP 内容时！

1. **代理与客户端**：使用伪造证书建立 TLS（让客户端信任代理）
2. **代理与目标服务器**：使用指纹建立 TLS（让目标服务器看到指定的浏览器指纹）

#### 为什么这样设计有意义？

```
客户端请求: GET /api/data
    ↓
[客户端 → 代理] TLS 加密
    ↓ 代理解密（可以看到内容）
代理可以看到: GET /api/data
    ↓ 代理重新发送
[代理 → 目标服务器] TLS 加密（使用指纹！）
    ↓
目标服务器看到: 来自 Chrome 142 的请求（指纹匹配）
```

**优势**：
- ✅ 代理可以查看和修改 HTTPS 内容（中间人功能）
- ✅ 代理与目标服务器连接时使用指纹（绕过指纹检测）
- ✅ 客户端仍然看到正常的 HTTPS 连接（使用伪造证书）

#### 代码中的实现

在 `handleConnect` 函数中：

```go
// 1. 与客户端建立 TLS（使用伪造证书）
tlsConn := tls.Server(clientConn, tlsConfig)  // 伪造证书

// 2. 与目标服务器建立 TLS（使用指纹！）
targetConn, err := p.dialTLSWithFingerprint(ctx, "tcp", host)
// ↑ 这里应用了指纹，目标服务器会看到指定的浏览器指纹

// 3. 双向转发（代理可以查看和修改内容）
go func() {
    io.Copy(targetConn, tlsConn)  // 客户端 → 目标服务器
}()
io.Copy(tlsConn, targetConn)      // 目标服务器 → 客户端
```

#### 总结

MITM 代理**确实在解析后转发**，而且**指纹确实有意义**：
- 代理解密客户端的数据（可以看到内容）
- 代理使用指纹与目标服务器建立连接（绕过指纹检测）
- 代理可以修改内容后再转发（中间人功能）

这就是为什么 MITM 代理需要处理 CONNECT 请求，并且指纹在代理与目标服务器连接时应用的原因。

## 使用方法

### 启动代理服务器

```bash
cd services/fastls-mitm
./mitm_proxy.exe -addr :8888 -browser chrome142
```

### 命令行参数

- `-addr`: 监听地址（默认: `:8888`）
- `-browser`: 浏览器类型（`chrome`, `chrome120`, `chrome142`, `chromium`, `edge`, `firefox`, `safari`, `opera`，默认: `chrome142`）
- `-ja3`: 自定义 JA3 指纹字符串（如果指定，将忽略 browser 参数）
- `-ja4r`: 自定义 JA4R 指纹字符串（如果指定，将忽略 browser 参数）
- `-ca-cert`: CA 证书文件路径（默认: `mitm-ca-cert.pem`）
- `-ca-key`: CA 私钥文件路径（默认: `mitm-ca-key.pem`）

### 配置代理

#### Windows

1. 打开"设置" > "网络和 Internet" > "代理"
2. 在"手动代理设置"中：
   - 打开"使用代理服务器"
   - 地址: `127.0.0.1`
   - 端口: `8888`

#### Linux/macOS

```bash
export http_proxy=http://127.0.0.1:8888
export https_proxy=http://127.0.0.1:8888
```

### 安装 CA 证书

#### Windows

1. 双击 `mitm-ca-cert.pem` 文件
2. 点击"安装证书"
3. 选择"本地计算机"
4. 选择"将所有证书放入以下存储"
5. 点击"浏览"，选择"受信任的根证书颁发机构"
6. 点击"确定"完成安装

#### Linux

```bash
# Ubuntu/Debian
sudo cp mitm-ca-cert.pem /usr/local/share/ca-certificates/fastls-mitm-ca.crt
sudo update-ca-certificates

# CentOS/RHEL
sudo cp mitm-ca-cert.pem /etc/pki/ca-trust/source/anchors/fastls-mitm-ca.crt
sudo update-ca-trust
```

#### macOS

```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain mitm-ca-cert.pem
```

## 使用示例

### curl

#### Windows (使用 schannel)

**重要**: Windows 上的 curl 使用 schannel，即使使用 `--cacert` 也会检查证书吊销状态。必须同时使用 `--ssl-no-revoke` 或安装证书到系统。

**方法 1: 使用 `--cacert` + `--ssl-no-revoke` 参数（推荐，无需修改系统）**
```bash
curl -x http://127.0.0.1:8888 --cacert mitm-ca-cert.pem --ssl-no-revoke https://tls.peet.ws/api/all
```

**方法 2: 仅使用 `--ssl-no-revoke` 参数（curl 7.44.0+）**
```bash
curl -x http://127.0.0.1:8888 --ssl-no-revoke https://tls.peet.ws/api/all
```

**方法 3: 将 CA 证书添加到系统信任的根证书颁发机构（最安全，一次配置永久有效）**
按照上面的"安装 CA 证书"步骤操作，然后正常使用：
```bash
curl -x http://127.0.0.1:8888 https://tls.peet.ws/api/all
```

**方法 4: 使用 `-k` 参数（不推荐，可能仍然报错）**
```bash
curl -x http://127.0.0.1:8888 -k https://tls.peet.ws/api/all
```

**注意**: 如果 curl 版本低于 7.44.0，`--ssl-no-revoke` 参数不可用，请使用方法 3 安装证书到系统。

#### Linux/macOS

```bash
# 使用 -k 跳过证书验证
curl -x http://127.0.0.1:8888 -k https://tls.peet.ws/api/all

# 或者使用 --cacert 指定 CA 证书
curl -x http://127.0.0.1:8888 --cacert mitm-ca-cert.pem https://tls.peet.ws/api/all
```

### Python

```python
import requests
import urllib3

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxy_url = "http://127.0.0.1:8888"
session = requests.Session()
session.proxies = {
    "http": proxy_url,
    "https": proxy_url
}
session.verify = False  # 禁用SSL验证（因为使用MITM证书）

response = session.get("https://tls.peet.ws/api/all")
print(response.text)
```

### Node.js

```javascript
const https = require('https');
const http = require('http');

const options = {
  hostname: 'tls.peet.ws',
  port: 443,
  path: '/api/all',
  method: 'GET',
  proxy: {
    host: '127.0.0.1',
    port: 8888
  },
  rejectUnauthorized: false  // 禁用证书验证
};

const req = https.request(options, (res) => {
  console.log(`状态码: ${res.statusCode}`);
  res.on('data', (d) => {
    process.stdout.write(d);
  });
});

req.on('error', (e) => {
  console.error(e);
});

req.end();
```

## 故障排除

### Windows curl 证书错误

如果遇到 `CERT_TRUST_REVOCATION_STATUS_UNKNOWN` 错误：

1. **推荐方法**: 使用 `--cacert` 参数指定 CA 证书文件
2. **简单方法**: 使用 `--ssl-no-revoke` 参数（如果 curl 版本支持）
3. **永久方法**: 将 CA 证书添加到系统信任的根证书颁发机构

### 代理连接失败

1. 确保代理服务器已启动
2. 检查防火墙设置
3. 确认代理地址和端口正确

### 证书生成失败

1. 检查是否有写入权限
2. 确保磁盘空间充足
3. 查看日志输出获取详细错误信息

## 注意事项

1. **安全警告**: MITM 代理会拦截和修改 HTTPS 流量，仅用于开发和测试环境
2. **证书信任**: 必须将 CA 证书添加到系统信任的根证书颁发机构，否则会出现证书错误
3. **性能影响**: MITM 代理会增加请求延迟，因为需要解密和重新加密流量
4. **指纹伪造**: 代理服务器会使用指定的浏览器指纹连接到目标服务器，确保指纹正确性

# Fastls MITM 代理服务器

中间人代理服务器，支持 TLS 指纹伪造。

> 当前状态：`v0.1.0` 正式版。正式产物只在 GitHub Releases 发布；其他软件包、镜像和应用商店不在发布范围内。

文档导航：[详细代理说明](./MITM_PROXY.md) · [委托模式](./DELEGATE_EXAMPLE.md) · [客户端示例](./example/README.md) · [开发流程](./DEVELOPMENT.md) · [产物签发验证](./ARTIFACTS.md)

## ⚠️ 安全声明

**重要警告**：本工具仅用于合法的安全测试、开发和调试目的。使用本工具时，您必须遵守以下规定：

### 合法使用范围

✅ **允许的使用场景**：
- 测试和开发环境中的应用程序调试
- 安全研究和渗透测试（在获得明确授权的情况下）
- 网络流量分析和调试（仅限您拥有或已获得授权的网络）
- 教育和学习目的
- 本地开发环境中的 HTTPS 请求调试

### 禁止用途

❌ **严禁用于以下目的**：
- 未经授权的网络流量拦截和监控
- 窃取他人敏感信息（密码、信用卡号、个人信息等）
- 违反法律法规的网络攻击活动
- 侵犯他人隐私的行为
- 任何非法或未经授权的活动

### 责任声明

1. **用户责任**：使用本工具的用户需自行承担所有法律责任
2. **无担保**：本工具按"现状"提供，不提供任何明示或暗示的担保
3. **风险自负**：使用本工具可能带来的任何风险由用户自行承担
4. **合规使用**：用户必须确保其使用方式符合当地法律法规

### 安全建议

🔒 **使用本工具时的安全建议**：
- 仅在受控的测试环境中使用
- 不要在生产环境中使用，除非您完全了解其安全影响
- 妥善保管 CA 证书和私钥，不要泄露给未授权人员
- 定期更换 CA 证书和私钥
- 使用完毕后及时删除生成的证书文件
- 不要在公共网络或不信任的网络中使用
- 确保只有授权人员可以访问代理服务器

### 法律合规

在使用本工具之前，请确保：
- 您已获得所有必要的授权和许可
- 您的使用行为符合当地法律法规
- 您了解并同意承担使用本工具可能带来的所有法律后果

**继续使用本工具即表示您已阅读、理解并同意遵守上述安全声明。**

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

## 从源码构建

需要 Go 1.26 或更高版本。仓库是独立 module，建议使用 `GOWORK=off`：

```bash
git clone https://github.com/FastTLS/fastls-mitm.git
cd fastls-mitm
go mod download
go build -o fastls-mitm .
./fastls-mitm -version
```

Windows 将输出文件改为 `fastls-mitm.exe`。传输链路基于 `fastls` + `ftransport`，不再依赖 `fhttp`。

## 使用方法

### 启动代理服务器

```bash
# Linux/macOS
./fastls-mitm -addr :8888 -browser chrome142

# Windows
fastls-mitm.exe -addr :8888 -browser chrome142

# 使用缩写参数
./fastls-mitm -a :8888 -b chrome142 -d
```

### 命令行参数

所有参数都支持完整和缩写两种形式：

| 完整参数 | 缩写 | 说明 | 默认值 |
|---------|------|------|--------|
| `-addr` | `-a` | 监听地址 | `:8888` |
| `-browser` | `-b` | 浏览器类型 | `chrome142` |
| `-ja3` | `-j3` | 自定义 JA3 指纹字符串 | - |
| `-ja4r` | `-j4` | 自定义 JA4R 指纹字符串 | - |
| `-ca-cert` | `-c` | CA 证书文件路径 | `mitm-ca-cert.pem` |
| `-ca-key` | `-k` | CA 私钥文件路径 | `mitm-ca-key.pem` |
| `-disable-connect` | `-dc` | 禁用 CONNECT 隧道请求 | `false` |
| `-verify-cert` | `-vc` | 验证目标服务器的 SSL 证书（默认不验证） | `false` |
| `-debug` | `-d` | 启用 Debug 模式 | `false` |
| `-version` | `-v` | 显示版本信息并退出 | - |
| `-help` | `-h` | 显示帮助信息并退出 | - |

**浏览器类型选项**：建议使用滚动别名 `chrome`、`edge`、`firefox`、`safari`、`opera` 或 `chromium`；需要固定实验条件时可以使用 `chrome150` 至 `chrome160`、`edge150` 至 `edge160`、`firefox151` 至 `firefox158`，以及兼容保留的历史选择器。

**注意**: 
- 如果指定了 `-ja3` 或 `-ja4r`，将忽略 `-browser` 参数
- 可以混合使用完整参数和缩写参数

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

### 基本使用

```bash
# 使用默认配置启动（监听 :8888，使用 chrome142 指纹）
./fastls-mitm

# 指定监听地址和浏览器类型
./fastls-mitm -addr :8888 -browser chrome142

# 使用缩写参数
./fastls-mitm -a :8888 -b chrome142

# 启用调试模式
./fastls-mitm -a :8888 -b chrome142 -debug
# 或使用缩写
./fastls-mitm -a :8888 -b chrome142 -d

# 使用自定义 JA3 指纹
./fastls-mitm -a :8888 -ja3 "771,4865-4866-4867,43-10-51-11-13-0-16-45,29-23-24,1"
# 或使用缩写
./fastls-mitm -a :8888 -j3 "771,4865-4866-4867,43-10-51-11-13-0-16-45,29-23-24,1"

# 查看版本信息
./fastls-mitm -version
# 或使用缩写
./fastls-mitm -v

# 查看帮助信息
./fastls-mitm -help
# 或使用缩写
./fastls-mitm -h

# 启用目标服务器证书验证（只连接有有效证书的服务器）
./fastls-mitm -addr :8888 -verify-cert
# 或使用缩写
./fastls-mitm -a :8888 -vc
```

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

## 请求头配置

MITM 代理支持通过请求头动态配置指纹和 HTTP/2 设置，优先级高于启动参数。

### 支持的请求头

| 请求头 | 说明 | 示例值 |
|--------|------|--------|
| `X-Mitm-Browser` | 浏览器类型 | `chrome142`, `firefox`, `safari` 等 |
| `X-Mitm-Ja3` | 自定义 JA3 指纹字符串 | `771,4865-4866-4867,43-10-51-11-13-0-16-45,29-23-24,1` |
| `X-Mitm-Ja4r` | 自定义 JA4R 指纹字符串 | `t13d1517h2_002f,0035,009c,009d,1301,1302,1303...` |
| `X-Mitm-H2Settings` | HTTP/2 设置字符串 | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` |
| `X-Mitm-Proxy` | 上级代理地址 | `http://user:pass@proxy:8080`、`https://proxy:8443` 或 `socks5://user:pass@proxy:1080` |

### 优先级说明

1. **请求头配置** > **启动参数配置** > **默认配置**
2. 如果同时设置了多个指纹类型（JA3、JA4R、Browser），按优先级使用：**JA3 > JA4R > Browser**

### HTTP/2 设置字符串格式

`X-Mitm-H2Settings` 支持以下格式：

```
格式: "SETTINGS|ConnectionFlow|HeaderPriority|SettingsOrder||PHeaderOrderKeys"

示例: "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
```

**各部分说明**：
- **SETTINGS**: HTTP/2 SETTINGS 帧设置，格式为 `ID:VALUE;ID:VALUE;...`
  - 例如：`1:65536;2:0;4:6291456;6:262144` 表示：
    - `1:65536` = HEADER_TABLE_SIZE: 65536
    - `2:0` = ENABLE_PUSH: 0
    - `4:6291456` = INITIAL_WINDOW_SIZE: 6291456
    - `6:262144` = MAX_HEADER_LIST_SIZE: 262144
- **ConnectionFlow**: 连接流控窗口大小，例如 `15663105`
- **HeaderPriority**: 头部优先级设置
  - 基础格式：`0`（只有 streamDep，会自动推断 weight 和 exclusive）
  - 完整格式：`0:256:true`（streamDep:weight:exclusive）
- **SettingsOrder**: SETTINGS 帧的顺序，用逗号分隔的字母，例如 `m,a,s,p`
  - `m` = HEADER_TABLE_SIZE (1)
  - `a` = ENABLE_PUSH (2)
  - `s` = INITIAL_WINDOW_SIZE (4)
  - `p` = MAX_HEADER_LIST_SIZE (6) 或 MAX_FRAME_SIZE (5)
- **PHeaderOrderKeys**（可选）: 伪头部顺序，用逗号分隔，例如 `:method,:authority,:scheme,:path`
  - 如果 SETTINGS 顺序为 `m,a,s,p`，会自动推导为 `:method,:authority,:scheme,:path`
  - 如果顺序为 `m,s,a,p`（Safari），会自动推导为 `:method,:scheme,:authority,:path`

**特殊设置**：
- Safari 使用扩展设置 `9:1`（NO_RFC7540_PRIORITIES）
- 示例：`2:0;3:100;4:2097152;9:1|10420225|0:256:false|m,s,a,p`

### 使用示例

#### curl 使用请求头配置

```bash
# 使用浏览器类型
curl -x http://127.0.0.1:8888 -H "X-Mitm-Browser: chrome142" https://tls.peet.ws/api/all

# 使用自定义 JA3 指纹
curl -x http://127.0.0.1:8888 -H "X-Mitm-Ja3: 771,4865-4866-4867,43-10-51-11-13-0-16-45,29-23-24,1" https://tls.peet.ws/api/all

# 使用自定义 HTTP/2 设置
curl -x http://127.0.0.1:8888 -H "X-Mitm-H2Settings: 1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p" https://tls.peet.ws/api/all

# 组合使用多个配置
curl -x http://127.0.0.1:8888 \
  -H "X-Mitm-Browser: chrome142" \
  -H "X-Mitm-H2Settings: 1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p" \
  -H "X-Mitm-Proxy: http://127.0.0.1:10809" \
  https://tls.peet.ws/api/all
```

#### Python 使用请求头配置

```python
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxy_url = "http://127.0.0.1:8888"
session = requests.Session()
session.proxies = {
    "http": proxy_url,
    "https": proxy_url
}
session.verify = False

# 使用请求头配置指纹和 HTTP/2 设置
headers = {
    "X-Mitm-Browser": "chrome142",
    "X-Mitm-H2Settings": "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
}

response = session.get("https://tls.peet.ws/api/all", headers=headers)
print(response.text)
```

#### 使用上级代理

```bash
# 通过请求头指定上级代理
curl -x http://127.0.0.1:8888 \
  -H "X-Mitm-Proxy: http://127.0.0.1:10809" \
  https://example.com

# 带认证的上级代理
curl -x http://127.0.0.1:8888 \
  -H "X-Mitm-Proxy: http://user:pass@proxy.com:8080" \
  https://example.com

# HTTPS 或 SOCKS5 上级代理
curl -x http://127.0.0.1:8888 \
  -H "X-Mitm-Proxy: socks5://user:pass@proxy.com:1080" \
  https://example.com
```

HTTP/HTTPS 上级代理通过 CONNECT 转发并支持 Basic 认证；SOCKS5 支持用户名/密码认证。HTTPS 上级代理默认使用系统根证书验证，嵌入式使用时可通过 `NewMITMProxyOptions.ProxyTLSRootCAs` 提供专用根证书。日志会移除代理 URL 中的用户名和密码。

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
3. 确认 `-ca-cert` 与 `-ca-key` 同时存在且互相匹配；损坏、非 CA 或不匹配的文件会被拒绝，不会被静默覆盖
4. 查看日志输出获取详细错误信息

## 高级功能

### 目标服务器证书验证

MITM 代理支持配置是否验证目标服务器的 SSL 证书：

**默认行为（不验证）**:
- 代理会忽略目标服务器的证书验证
- 可以连接使用自签名证书的服务器
- 适合测试环境、内网服务、开发调试

**启用验证（`-verify-cert`）**:
- 代理会验证目标服务器的证书有效性
- 只连接有有效证书的服务器
- 如果目标服务器使用自签名证书，连接将失败
- 适合生产环境，确保目标服务器证书有效

**使用示例**:
```bash
# 默认模式：可以连接自签名证书的服务器（如 fastls-target -tls）
./fastls-mitm -addr :8888

# 启用验证：只连接有有效证书的服务器
./fastls-mitm -addr :8888 -verify-cert
```

### 资源管理

MITM 代理会自动管理连接资源：

- **客户端断开时自动清理**: 当客户端连接断开时，代理会自动关闭对应的服务端连接，避免资源泄漏
- **HTTP/2 连接复用**: 支持 HTTP/2 连接复用，提高性能
- **连接超时处理**: 自动处理连接超时和异常情况
- **安全停止**: 收到 Ctrl+C、SIGINT 或 SIGTERM 后停止监听，关闭已劫持的 CONNECT 隧道，并等待普通 HTTP 请求结束

### HTTP/2 设置自动推导

当使用 `X-Mitm-H2Settings` 时，如果 SETTINGS 顺序字符串包含 4 个字母且都是 `m,a,s,p` 的组合，会自动推导伪头部顺序：

- `m,a,s,p` → `:method,:authority,:scheme,:path`（Chrome/Edge）
- `m,s,a,p` → `:method,:scheme,:authority,:path`（Safari）
- `m,p,a,s` → `:method,:path,:authority,:scheme`（Firefox）

如果顺序字符串不符合上述模式，可以通过在字符串末尾添加 `||:method,:authority,:scheme,:path` 显式指定。

### 扩展 HTTP/2 设置支持

MITM 代理支持扩展的 HTTP/2 设置，例如 Safari 使用的 `NO_RFC7540_PRIORITIES`（设置 ID 9）：

```
示例: "2:0;3:100;4:2097152;9:1|10420225|0:256:false|m,s,a,p"
```

其中 `9:1` 表示 `NO_RFC7540_PRIORITIES` 设置为 1。

## 注意事项

### 技术注意事项

1. **证书信任**: 必须将 CA 证书添加到系统信任的根证书颁发机构，否则会出现证书错误
2. **性能影响**: MITM 代理会增加请求延迟，因为需要解密和重新加密流量
3. **指纹伪造**: 代理服务器会使用指定的浏览器指纹连接到目标服务器，确保指纹正确性
4. **连接管理**: 代理会自动管理连接生命周期，客户端断开时会自动清理服务端连接
5. **HTTP/2 设置**: 通过 `X-Mitm-H2Settings` 配置的 HTTP/2 设置会覆盖浏览器默认配置，优先级最高
6. **目标服务器证书验证**: 
   - **默认行为**（不验证）: 代理会忽略目标服务器的证书验证，可以连接自签名证书的服务器（适合测试环境）
   - **启用验证**（`-verify-cert`）: 代理会验证目标服务器的证书，只连接有有效证书的服务器（适合生产环境）
   - **使用建议**: 
     - 测试环境、内网服务、自签名证书 → 使用默认模式（不验证）
     - 生产环境、需要确保目标服务器证书有效 → 使用 `-verify-cert` 参数

### 安全注意事项

⚠️ **重要提醒**：
- MITM 代理会拦截和修改 HTTPS 流量，**仅用于开发和测试环境**
- 在生产环境中使用前，请仔细评估安全风险
- 确保只有授权人员可以访问代理服务器
- 妥善保管 CA 证书和私钥，避免泄露
- 使用完毕后及时清理证书文件
- 请参考文档开头的"安全声明"部分，了解合法使用范围和禁止用途

## 测试与 Actions

本地最小验证：

```bash
go mod verify
go test ./...
go test -race ./...
go vet ./...
go build ./...
```

CI 覆盖 Windows、Linux、macOS 与 Go 1.26.10/1.27.3，执行依赖策略、单元及真实 TLS/HTTP/2 交接测试、竞态检测、覆盖率、静态检查、全包构建和 CLI 冒烟测试。`main` 分支构建临时开发包；`v*` 标签生成六个平台正式包、SHA-256 校验和与 Sigstore/GitHub 来源证明，并只发布到 GitHub Releases。

端到端测试只使用环回目标，并在临时目录生成独立 CA；覆盖普通 HTTP 转发、HTTPS CONNECT 解密、客户端 HTTP/1.1 到目标 HTTP/2 的协议交接、控制头剥离、证书签发链和 CONNECT 认证拒绝。CONNECT 在返回 `200 Connection Established` 前完成认证，拒绝时返回 `407`。

测试套件还会现场构建并启动 `fastls-mitm`，使用临时 CA，通过真实代理端口验证 HTTP 与 HTTPS 请求；不会写入仓库证书或访问公网。

完整门禁见 [DEVELOPMENT.md](./DEVELOPMENT.md)，下载和验证发布产物见 [ARTIFACTS.md](./ARTIFACTS.md)。

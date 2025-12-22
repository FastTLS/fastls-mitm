# 中间人代理服务使用说明

## 功能特性

- ✅ 自动生成CA根证书（有效期15年）
- ✅ 动态为每个域名生成SSL证书
- ✅ 支持TLS指纹设置（JA3/JA4R或浏览器类型）
- ✅ 支持HTTP和HTTPS代理
- ✅ 证书缓存机制，提高性能

## 编译

```bash
cd services/fastls-mitm
go build -o mitm_proxy.exe main.go
```

## 使用方法

### 基本用法

```bash
# 使用默认配置（监听8888端口，Chrome142指纹）
./mitm_proxy.exe

# 指定监听地址
./mitm_proxy.exe -addr :8888

# 指定浏览器指纹
./mitm_proxy.exe -addr :8888 -browser chrome142

# 使用自定义JA3指纹
./mitm_proxy.exe -addr :8888 -ja3 "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0"

# 使用自定义JA4R指纹
./mitm_proxy.exe -addr :8888 -ja4r "t13d5911_002f,0032,0033,0035,0038,0039,003c,003d,0040,0067,006a,006b,009c,009d,009e,009f,00a2,00a3,00ff,1301,1302,1303,c009,c00a,c013,c014,c023,c024,c027,c028,c02b,c02c,c02f,c030,c050,c051,c052,c053,c056,c057,c05c,c05d,c060,c061,c09c,c09d,c09e,c09f,c0a0,c0a1,c0a2,c0a3,c0ac,c0ad,c0ae,c0af,cca8,cca9,ccaa_000a,000b,000d,0016,0017,0023,002b,002d,0033_0403,0503,0603,0807,0808,0809,080a,080b,0804,0805,0806,0401,0501,0601,0303,0301,0302,0402,0502,0602"
```

### 命令行参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-addr` | 监听地址 | `:8888` |
| `-browser` | 浏览器类型 | `chrome142` |
| `-ja3` | 自定义JA3指纹 | 空 |
| `-ja4r` | 自定义JA4R指纹 | 空 |
| `-ca-cert` | CA证书文件路径 | `mitm-ca-cert.pem` |
| `-ca-key` | CA私钥文件路径 | `mitm-ca-key.pem` |

### 支持的浏览器类型

- `chrome` - Chrome浏览器
- `chrome120` - Chrome 120版本
- `chrome142` - Chrome 142版本
- `chromium` - Chromium浏览器
- `edge` - Microsoft Edge浏览器
- `firefox` - Firefox浏览器
- `safari` - Safari浏览器
- `opera` - Opera浏览器

## 配置代理

### 1. 安装CA证书

首次运行会生成CA证书文件：
- `mitm-ca-cert.pem` - CA根证书
- `mitm-ca-key.pem` - CA私钥（请妥善保管）

**Windows:**
1. 双击 `mitm-ca-cert.pem` 文件
2. 点击"安装证书"
3. 选择"本地计算机"
4. 选择"将所有证书放入下列存储"
5. 浏览并选择"受信任的根证书颁发机构"
6. 完成安装

**Linux:**
```bash
sudo cp mitm-ca-cert.pem /usr/local/share/ca-certificates/mitm-ca.crt
sudo update-ca-certificates
```

**Mac:**
```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain mitm-ca-cert.pem
```

### 2. 配置系统代理

**Windows:**
- 设置 -> 网络和Internet -> 代理
- 手动代理设置
- HTTP代理: `127.0.0.1:8888`
- HTTPS代理: `127.0.0.1:8888`

**Linux/Mac:**
```bash
export http_proxy=http://127.0.0.1:8888
export https_proxy=http://127.0.0.1:8888
```

**浏览器扩展:**
- Chrome: SwitchyOmega
- Firefox: FoxyProxy

## 使用示例

### 示例1: 使用Chrome142指纹

```bash
./mitm_proxy.exe -addr :8888 -browser chrome142
```

### 示例2: 使用自定义JA3指纹

```bash
./mitm_proxy.exe -addr :8888 -ja3 "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0"
```

### 示例3: 监听所有网络接口

```bash
./mitm_proxy.exe -addr 0.0.0.0:8888 -browser firefox
```

## 工作原理

1. **CA证书生成**: 首次运行自动生成CA根证书（有效期15年）
2. **动态证书生成**: 为每个访问的域名动态生成SSL证书
3. **证书缓存**: 生成的证书会被缓存，避免重复生成
4. **TLS指纹**: 连接到目标服务器时使用指定的TLS指纹
5. **双向转发**: 在客户端和目标服务器之间双向转发数据

## 注意事项

1. **安全性**: CA私钥文件（`mitm-ca-key.pem`）请妥善保管，不要泄露
2. **证书信任**: 必须将CA证书添加到系统信任的根证书颁发机构
3. **防火墙**: 确保防火墙允许代理端口（默认8888）
4. **性能**: 证书生成和缓存机制已优化，支持高并发
5. **法律合规**: 仅用于合法的网络调试和安全研究

## 故障排除

### 问题1: 证书不受信任

**解决方案**: 确保已将CA证书添加到系统信任的根证书颁发机构

### 问题2: 连接失败

**解决方案**: 
- 检查代理端口是否正确
- 检查防火墙设置
- 查看日志输出

### 问题3: TLS握手失败

**解决方案**: 
- 检查目标服务器是否支持指定的TLS版本
- 尝试使用不同的浏览器指纹
- 查看详细日志

## 日志输出

启动时会显示：
- 监听地址
- CA证书路径
- 使用的指纹类型
- 配置信息

运行时会记录：
- 证书生成日志
- 连接日志
- 错误信息

## 技术细节

- **证书有效期**: CA证书15年，域名证书1年
- **证书算法**: RSA 2048位
- **TLS版本**: 支持TLS 1.2和TLS 1.3
- **并发支持**: 使用goroutine处理多个连接


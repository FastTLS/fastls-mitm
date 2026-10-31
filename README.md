# Fastls MITM 代理

[English documentation](https://fasttls.github.io/en/ecosystem/fastls-mitm)

为经过授权的 HTTPS 调试与网络兼容性测试提供 HTTP 代理。代理解密客户端流量，再使用选定的 TLS/HTTP 配置连接目标；它能读取经过它的明文，必须作为敏感基础设施管理。

[完整代理说明](MITM_PROXY.md) · [委托模式](DELEGATE_EXAMPLE.md) · [发布包](https://github.com/FastTLS/fastls-mitm/releases)

当前发行目标为 **v0.1.2**，固定核心 `v0.1.3-0.20261030152832-0dc4eea0f32e`；可信地址策略与未指定目标拒绝见 [ADDRESS_POLICY.md](ADDRESS_POLICY.md)。旧二进制须升级才能获得修正。

## 安装与启动

从 Releases 下载匹配系统和架构的产物，按 [ARTIFACTS.md](ARTIFACTS.md) 校验。普通用户无需 Go。从源码构建需要 Go 1.26+：

```sh
git clone https://github.com/FastTLS/fastls-mitm.git
cd fastls-mitm
go build -o fastls-mitm .
./fastls-mitm -addr 127.0.0.1:8888 -browser chrome -verify-cert
```

Windows 使用 `go build -o fastls-mitm.exe .` 和 `./fastls-mitm.exe`。查看当前版本的 `-help` 和 `-version`，不要把其它分支新增参数用于旧发布包。默认监听地址为 `:8888`，上述命令显式限定环回地址；历史默认目标证书校验为关闭，因此示例显式启用 `-verify-cert`。

## 首次请求

启动后生成 `mitm-ca-cert.pem` 与 `mitm-ca-key.pem`。仅把 CA 证书交给授权客户端，私钥留在代理端，不应提交仓库或分发。使用应用级信任，避免为短期测试改变系统全局信任：

```sh
curl --proxy http://127.0.0.1:8888 --cacert mitm-ca-cert.pem https://example.com/
```

`--cacert` 校验客户端到代理的证书；`-verify-cert` 校验代理到目标的证书，这是两条独立的 TLS 连接。不要用 `-k` 或关闭 Python verify 代替正确配置 CA。

Python 客户端示例（先安装 requests）：

```python
import requests

with requests.Session() as session:
    session.proxies = {"http": "http://127.0.0.1:8888", "https": "http://127.0.0.1:8888"}
    session.verify = "mitm-ca-cert.pem"
    response = session.get("https://example.com/", timeout=30)
    response.raise_for_status()
    print(response.text)
```

## 支持什么

- HTTP 代理、HTTPS CONNECT 后的授权 MITM、浏览器选择器、自定义 JA3/JA4R。
- 启动级及请求级配置、HTTP/2 设置、上级代理和委托模式，具体入口见详细说明。
- 在代理到目标一侧应用配置；客户端到代理的 TLS 由客户端决定。

## 不支持与风险边界

- 不是透明无解密隧道，也不是完整浏览器；不能保证通过风控或与任何真实浏览器完全一致。
- 证书固定、客户端自定义信任链或双向认证等场景可能拒绝 MITM，不能保证任意应用可接入。
- 不把此工具当作任意协议 VPN、HTTP/3/QUIC 代理或完备的多租户服务。
- 不要向不受信任网络开放未认证实例；日志、证书私钥和捕获流量均需控制访问。请求头配置应仅允许可信调用方设置。
- 历史详细说明中的选择器、默认值和示例须与安装版本的帮助对应。Windows curl 的证书/吊销行为随 TLS 后端和环境变化；优先配置信任与可用的吊销检查条件。

## 更多文档

[已发布响应契约](RESPONSE_CONTRACT.md)：默认路径与策略路径的正文、Trailer、跳转、连接复用和取消行为，以及真实连接测试入口。服务 v0.1.2 已包含这些修复。

[已发布地址策略与资源限额](ADDRESS_POLICY.md)：包含新核心下的 CONNECT 检查、接入连接、请求与隧道配额。v0.1.2 独立正式二进制包含这些选项；策略需显式启用。

[代理参数与行为](MITM_PROXY.md) · [委托示例](DELEGATE_EXAMPLE.md) · [客户端示例](example/README.md) · [源码开发](DEVELOPMENT.md) · [产物验证](ARTIFACTS.md)

## 详细文档与问题反馈

- [使用文档](https://fasttls.github.io/ecosystem/)：安装、功能、参数与排错。
- [版本与发布说明](https://github.com/FastTLS/fastls-mitm/releases)：正式版本、开发版本和产物边界。
- [问题反馈](https://github.com/FastTLS/fastls-mitm/issues)：请提供版本、系统架构、脱敏后的最小示例与错误；不要提交凭据、Cookie、私钥或个人数据。

## 开源协议与第三方声明

FastTLS 自有代码采用 [Apache-2.0](LICENSE)，见 [NOTICE](NOTICE)。第三方依赖保留各自授权，分发时保留随包材料。

## 使用边界与免责声明

仅在拥有权限的系统、数据和网络上使用，并遵守适用法律、服务条款及隐私要求。软件按许可证约定以“现状”提供，不承诺可用性、特定用途适用性、第三方服务放行、匿名性或与真实浏览器完全一致。浏览器名称和版本用于描述配置，不表示获得相应厂商认证或背书。部署方负责访问控制、密钥和个人信息保护、请求限额及数据备份；担保排除与责任限制以随附许可证及适用法律为准。本说明不改变许可证授予的权利或新增许可限制。

## Optional audit (released since v0.1.1)

[Optional audit events and limits](AUDIT.md): disabled by default, with fixed redacted fields and bounded drain. Available in service v0.1.1 and v0.1.2; auditing remains opt-in.

发行门禁接受同一完整提交的成功候选，或独立重新核验过的可信 main 祖先证明。复用要求源码、模块、生成输入、原生命令、工具链及平台配置一致，全部必需任务成功；未知差异、缺失、失败、取消和任意跳过均阻止签发。RPC 的跨仓契约单独检查固定引用、协议测试与执行配置，不随普通 Go 证明自动豁免。归档继续按实际生产提交构建、记录 vcs.revision 并签名，不将旧字节改标为新提交。main 不自动重复生成开发归档，正式标签每个平台只构建一次。

# 开发说明

## 安全与测试边界

fastls-mitm 会解密经明确配置、明确授权的 HTTPS 流量。开发测试必须使用自有或本地测试目标，不得把测试代理接入未授权流量。测试生成的 CA 私钥只放在临时目录，测试结束后删除；禁止提交 CA 私钥、会话内容或真实凭据。

## 开发基线

仓库是独立 Go module。设置 `GOWORK=off`，不得依赖父目录工作区、未提交的本地模块或 `replace` 指令。

```bash
go mod download
go mod verify
go test ./...
go vet ./...
go build ./...
```

最低基线为 Go 1.26；CI 矩阵为 Go 1.26.10/1.27.3 × Ubuntu 24.04/Windows 2022/macOS 15。

## 提交前检查

```bash
go mod tidy
git diff --exit-code -- go.mod go.sum
go test -race ./...
go test -covermode=atomic -coverprofile=coverage.out ./...
go tool cover -func=coverage.out
go build -o build/fastls-mitm .
./build/fastls-mitm -version
```

代理路径修改至少应覆盖：普通 HTTP、CONNECT、客户端 TLS、到目标的 TLS、HTTP/1.1 响应、HTTP/2 交接、错误关闭和取消传播。优先使用 `httptest` 与环回地址，避免公网依赖。

需要创建代理实例的测试必须通过 `NewMITMProxyOptions.CACertPath` 与 `CAKeyPath` 指向 `t.TempDir()`；不得在仓库目录写入测试 CA。CONNECT 认证测试必须确认拒绝发生在劫持连接和发送成功响应之前。上级代理变更必须分别覆盖 HTTP Basic、HTTPS 证书校验、SOCKS5 用户名/密码、握手取消和日志凭据脱敏。生命周期变更必须验证 context 取消、监听器停止和已劫持隧道关闭。

`binary_e2e_test.go` 会构建并启动当前 MITM CLI，使用临时 CA 和环回 HTTP/HTTPS 目标验证真实代理进程。不得写入仓库 CA，也不得访问公网。

## CI 门禁

`.github/workflows/ci.yml` 执行：

1. module 校验、`go mod tidy` 零差异、禁止 `replace`、禁止 `fhttp`。
2. 三平台、两个 Go 版本的测试、`go vet` 和全包构建。
3. Linux 竞态检测、覆盖率、二进制构建及 `-version` 冒烟测试。

所有第三方 Actions 固定到完整提交 SHA；Pull Request 只获得读取权限。

## 开发产物

合入 `main` 或手动运行 `Development artifacts` 后，工作流生成临时开发产物。推送受审的 `v*` 标签时，同一流程在校验、交叉构建、计算摘要、签发和自验证全部成功后创建正式 GitHub Release，且不向其他渠道发布。详见 [ARTIFACTS.md](./ARTIFACTS.md)。

## 变更约定

策略资源选项需要显式新核心工作区验证：运行`go test -count=3 -tags mitm_policy_e2e -timeout 180s ./...`与对应race。连接测试要包含请求头未完成、keepalive和劫持后的租约保留；流量测试要包含预读ClientHello、握手、同隧道多请求累计、截断错误和出站取消。`FuzzPolicyTrafficBudget`是无网络纯字节回归，普通公开依赖质量Action也会运行20秒；不要把GOWORK=off的旧核心拒绝用例当成策略已生效。

- 修改命令参数时同步 `help.go`、README 和示例。
- 修改动态请求头时同步代理文档并增加优先级测试。
- 修改指纹选择范围时覆盖规范选择器、兼容别名和无效输入。
- 新依赖必须在独立 module 下解析，且不能重新引入 `fhttp`。
- 不得降低证书或私钥保护来简化测试。

# MITM 目标地址策略（开发源码）

P03-B3新增能力，尚未发布。正式fastls-mitm v0.1.0没有本页选项，当前公开核心fastls v0.1.1也没有所需能力。默认独立构建仍使用正式依赖；显式启用但核心不支持时，在监听和生成CA之前拒绝启动，不静默退回旧转发。

## 启动配置

`-address-policy /trusted/path/policy.json`读取可信运维文件，最大1MiB，启动时严格校验并固定规则；未知/重复键、null数组、非法规则及尾随值拒绝。文件与Fetch/RPC使用同一模式：

```json
{
  "allow_schemes": ["https"],
  "allow_hosts": ["api.example.test"],
  "allow_ports": [443],
  "allow_cidrs": ["192.0.2.0/24"],
  "deny_cidrs": []
}
```

示例为文档域名/地址，须替换为实际获准目标。非空允许维度同时满足，CIDR拒绝优先；空列表/省略不自动禁止私网、回环或元数据服务。规则不热更新，请求头、Delegate的请求Options不能清除客户端固定策略。

启用时还要求核心实现`CheckAddressPolicy(context.Context, *http.Request, string) error`，提供无目标套接字的预检和规范化origin绑定。新源码工作区提供`verify-p03-mitm.work`；普通正式依赖版本仍不能启用，需后续核心发布与依赖协调。测试和只读手动Action分别记录这两类构建，不用本地replace冒充已发布能力。

## CONNECT 与实际出站

认证成功后、200 Connection Established之前，按HTTPS目标校验CONNECT的scheme、authority、端口及全部DNS答案；禁止目标直接返回403，不生成该目标叶证书、不连接目标。语法错误可能由HTTP解析器提前返回400。禁用CONNECT仍为405，认证失败仍为407。

允许的CONNECT只建立客户端到本代理的TLS，SNI必须与原CONNECT目标相符；每个解密请求的URL、Host、有效端口及scheme也绑定该origin。即便两个地址都在白名单，也不能在同一隧道中切换目标、端口或明文scheme。无SNI的IP客户端仍检查每个HTTP请求。

预检不是可复用的DNS许可。每次真正出站仍由核心重新解析、校验全部答案并只连接数值IP快照，防止预检后重绑定。保持原URL/Host/SNI和`-verify-cert`行为。策略路径不调用旧的自定义拨号器、手写H1发送器或透明隧道；客户端侧使用标准HTTP1服务器，上游可为H1/H2。连续客户端请求可复用隧道，但当前每个请求单独建立核心出站传输，不保证上游连接池复用。

代理头、Delegate.ParentProxy/Options.Proxy在本模式明确拒绝，父代理选择失败也不得直连回退。HTTP3指纹、WebSocket/Upgrade、嵌套CONNECT、透明转发及强制HTTP11控制不开放，不因安全检查失败切换旧路径。代理认证仅在普通代理请求或CONNECT阶段执行，加密请求不必再次携带代理凭据；这些凭据不会转给origin。

Delegate.Connect/Auth负责CONNECT；每条解密HTTP分别调用BeforeRequest、BeforeResponse和Finish，并使用独立Context。CONNECT的Data不会自动复制，内层Data提供`mitm.policy.connect_authenticated`标志。CONNECT上的指纹头仅在请求级没有覆写时继承；可信Delegate自身的任意外部操作不属于本代理连接策略的强制边界。

## 请求边界与转发差异

`-policy-max-request-bytes N`只用于策略模式：默认4MiB，0在启用策略时选择默认值，允许1..67108864。CLI显式指定此参数但未启用地址策略会拒绝启动。Go选项`PolicyMaxRequestBytes`的零值同样选择默认值。

本模式先限额读取完整正文，再转发原始字节及EOF后完整Trailer；固定长度和chunked超限都返回413，`X-Proxy-Error: request_too_large`，不开始目标拨号。二进制正文、多值头及响应Trailer有回归覆盖；过滤Connection指定的hop字段、代理认证和X-Mitm-*控制头，重新编码传输分帧。该单请求预算不是总内存或并发上限，也不是流式大文件转发承诺。

策略模式的外层和隧道内HTTP服务器配置64KiB MaxHeaderBytes（遵循标准库解析预算）、30秒读头/读写/空闲限制；每个转发请求上下文最多30秒，客户端握手另有30秒预算。停机关闭已登记连接并取消活动出站请求。

## 请求并发、隧道数量与寿命（P03-B4开发源码）

以下都是可信启动配置，不从请求头/DTO读取，默认0保持原有不限制行为。CLI显式设置但未启用address-policy时拒绝启动，Go选项非零也需策略；负值/超界在生成CA或监听前拒绝。

- `-policy-max-inflight N` / `PolicyMaxInflight`：0..65536。普通HTTP与所有隧道内解密请求共享请求名额；认证后、正文缓存/DNS/出站前申请，覆盖响应流复制。CONNECT本身不占此名额，健康检查不占用。
- `-policy-max-tunnels N` / `PolicyMaxTunnels`：0..65536。认证后、目标预检/证书生成/劫持/200前申请，包含正在预检、握手、空闲和活动的CONNECT；失败、断连、到期或停机退出时释放。不是所有入站TCP连接的总数上限。
- `-policy-tunnel-max-age 5m` / `PolicyTunnelMaxAge`：0..24h。非零时从已登记的隧道连接开始计时，握手或持续传输不会续期；到期关闭客户端套接字并取消其活动出站上下文。该选项不覆盖CONNECT之前的DNS预检时间；预检有核心自己的有限超时。到期属于连接终止，不伪装为一条成功HTTP响应。

名额满时立即HTTP503，`X-Proxy-Error: overloaded`，关闭本次请求连接且不等待队列，不访问目标；认证失败仍优先407。请求名额与隧道名额独立，空闲隧道不占用请求名额。设置单请求正文限制和并发限制可约束相关缓存数量，但不等于进程总内存、全局TCP连接数、速率或隧道累计字节配额。旧模式不受这些选项自动影响。

本模式直接返回上游3xx，由调用者决定下一次请求；下一次经代理的请求再次校验。不会替客户端自动跟随Location。上游正文截断会终止下游响应，不伪装为正常EOF。普通旧模式仍保持旧行为，不因新增选项自动改变。

## 接入连接数与隧道累计字节（P03-B5开发源码）

这些选项同样只从可信启动配置读取，默认0禁用，显式CLI参数需address-policy；非法值在生成CA/监听前拒绝。

- `-policy-max-connections N` / `PolicyMaxConnections`：0..65536。限制本实例用户态接入TCP连接总数，包含未完成HTTP头、HTTP keepalive、普通活动请求以及劫持后的CONNECT。满额时Accept后立即关闭新连接，不进入HTTP解析、不排队，所以不是HTTP503；健康请求也需连接名额，不应误当作服务故障。已有连接关闭后才能接入替代连接。它不限制内核backlog或TCP握手包，也不是出站池大小限制。
- `-policy-tunnel-max-read-bytes N` / `PolicyTunnelMaxReadBytes`：0..1099511627776（1TiB）。每个CONNECT累计从客户端交付给TLS服务器的字节上限。
- `-policy-tunnel-max-write-bytes N` / `PolicyTunnelMaxWriteBytes`：相同范围。每个CONNECT累计由TLS服务器实际写向客户端的字节上限。

两个字节预算独立，并非共用一个总池；如需双向有限，应分别设置，二者之和是该隧道两个方向的配置上界。握手、TLS记录开销与已被HTTP服务器预读的ClientHello都计入；CONNECT请求/200不计入。该口径不含TCP包头、重传、内核已接收但尚未交付TLS层的数据，也不等于应用解压后正文或全实例流量。普通HTTP不属于CONNECT字节预算。

预算跨同一隧道内的多次请求累计，不因活动或请求结束重置。任一方向达到上限即关闭整个套接字并取消活动出站；不会保证最后一条TLS记录或HTTP正文完整，不追加成功响应或静默重连。调用方必须检查读取/握手错误。读取与写入分别串行计费，不因后台阻塞Read占用发送额度而死锁。

接入连接名额在底层关闭时幂等归还；请求/隧道名额在对应处理退出时归还。Shutdown宽限期到期后，策略模式强制关闭普通连接，避免未完成请求头或慢请求继续持有名额，同时仍返回原deadline错误；不能把强制清理表述为优雅完成。已劫持隧道仍由原登记表关闭。

例如，已链接新核心的开发二进制可使用以下启动配置（先准备上文策略文件；当前正式Release不包含这些选项）：

```text
fastls-mitm -addr 127.0.0.1:8888 -address-policy policy.json -policy-max-connections 128 -policy-max-inflight 16 -policy-max-tunnels 32 -policy-tunnel-max-age 5m -policy-tunnel-max-read-bytes 16777216 -policy-tunnel-max-write-bytes 67108864
```

连接额度还需容纳健康检查、普通HTTP和空闲连接，不要只按活跃CONNECT数量配置。TLS握手也会消耗字节预算，过小的值会在访问任何目标之前中断握手。

## 错误、网关链路与日志

策略拒绝为HTTP403，带`X-Proxy-Error: address_denied`和`X-Proxy-Error-Reason`；正文只含固定Reason，不回显目标URL凭据或查询。其他上游/父代理选择错误为通用502。TLS SNI/ALPN拒绝发生在握手阶段，关闭连接而非伪造一条已加密HTTP响应。不是完整审计或所有现有日志已脱敏的声明。

Fetch/JSON-RPC/gRPC可在自身策略关闭时通过本受限MITM作为parent_proxy，已验证允许/拒绝链路。不能同时假定服务本地策略已支持父代理：核心当前仍在启用本地策略时拒绝Proxy。MITM的403经过上游适配层可能表现为代理请求失败，不自动成为适配器本地的address_denied分类。

## 验证与未完成项

默认独立构建门禁覆盖旧核心拒绝及原代理兼容；显式工作区使用`go test -count=3 -tags mitm_policy_e2e -timeout 180s ./...`验证生效能力。覆盖CONNECT前拒绝、实际目标TCP连接计数、SNI/origin越界、H1/H2、二进制/Trailer、精确请求限额、流水ClientHello、认证和停机取消。RPC的policy_e2e包含三入口经受限MITM链路。缺少新核心时正向门禁失败，不跳过。

仍未完成正式核心依赖升级、生效策略跨仓远端矩阵验收、速率/全实例累计流量限制、完整审计接口及FFI完整Spec输入。Fetch/RPC请求大小配置与本模式的请求/隧道并发、寿命、接入TCP名额及双向累计TLS字节预算已在开发源码增加；Fetch/RPC仍没有这里的全局接入TCP名额。本轮不发布或签发新产物。

# knok 一期 MVP 设计文档（Spec）

- 日期：2026-09-26
- 状态：已确认（brainstorming 流程产出）
- 范围：完整一期 MVP —— 协议库、客户端、eBPF 数据面、knokd 守护进程、每网卡管理
- 实施策略：垂直切片（walking skeleton）优先，增量 M1–M6

---

## 1. 目标与非目标

**目标**：用 eBPF + Go 实现单包授权（SPA）。服务器默认零开放端口，客户端发送一个加密、签名、防重放的包，knokd 验证后在内核 allowlist 中授权该源 IP 访问指定端口，TTL 到期自动失效。

**一期验收标准（用户确认）**：功能验收——完整授权链路跑通（`knok auth` → 敲门 → 隐藏端口可访问 → TTL 到期自动关闭；UDP 与 TCP SYN 两种传输；keygen/enroll/revoke 可用；崩溃重启不断授权）。测试体系、性能基准、安全审查不作为一期验收门槛，但测试作为开发手段存在（§9）。

**非目标（一期不做）**：NAT/网关穿透的 eBPF 复刻（nftables 兜底）、SPA over HTTP、远程命令执行（fwknop ENABLE_CMD_EXEC 属反模式，永久放弃）、Netfilter-BPF 后端、XDP 抗 DoS fast path（均为二期）、Windows 客户端 raw SYN 模式、多服务器策略中心。

**已确认的环境与边界决策**：

| 决策点 | 结论 |
|---|---|
| 开发验证环境 | 云 VPS，Ubuntu 24.04/新内核（≥6.8），首发后端 TCX |
| 防火墙边界 | knokd 只自建 `inet knok` 独立表，不碰用户已有防火墙 |
| SPA 传输 | UDP 专用端口（默认 4242）+ TCP SYN 载荷携带 |
| 密钥注册 | 服务端配置文件为真相源 + `knok enroll --via ssh` 便捷命令 |
| 代码目录 | 全部实现于本仓库（/Users/zhouyu/Documents/learn/knok） |

---

## 2. 分层架构（端口-适配器）

依赖方向只允许向下/向接口。**隔离性三条硬规则**：

1. `internal/core` 的 import 永不出现 cilium/ebpf、vishvananda/netlink、google/nftables——CI 用 `go list` 断言防腐蚀；
2. core 在非 Linux（macOS）上 `go test ./...` 全绿：测试用内存适配器（memAllowlist、fakePacketSource、fakeClock）；
3. eBPF 与 Go 的契约（ringbuf 事件结构、map 布局）定义于 `bpf/` + `platform/ebpf/types.go`，bpf2go 生成保证一致，core 不感知。

```
Layer 0 · pkg/protocol        线格式编解码、XChaCha20-Poly1305、Ed25519、X25519、
                              测试向量。纯计算，零 OS 依赖，对外可 import。
Layer 1 · internal/core       auth/（验证管线） policy/（密钥策略模型）
                              audit/（结构化审计事件） ports/（接口定义：
                              PacketSource/Allowlist/Firewall/NicManager/
                              Clock/AuditSink）
Layer 2 · internal/platform   ebpf/（map 实现 + RingbufPacketSource + AttachBackend）
                              nftables/（inet knok 表声明式同步）
                              netlink/（NicManager：接口发现/reconcile 事件源）
                              全部 //go:build linux
Layer 3 · cmd/                knokd/（组装根：能力探测→选适配器→注入 core→主循环）
                              knok/（客户端 CLI，Transport 抽象）
bpf/                          eBPF C 源码 + bpf2go 生成物
```

**core 主循环形态**（全接口，无平台依赖）：

```go
func (a *Authenticator) Run(ctx context.Context) error {
    for pkt := range a.source.Packets() {
        d := a.pipeline.Evaluate(pkt, a.clock.Now()) // 纯函数式验证管线
        if d.Allowed {
            a.allowlist.Grant(d.SrcIP, d.Ports, d.Expiry)
        }
        a.audit.Emit(d)
    }
}
```

---

## 3. 协议设计（pkg/protocol）

### 3.1 线格式 v1（UDP 包体与 TCP SYN 载荷共用）

```
偏移  字段             说明
0     magic[4] "KNOK"  eBPF 特征过滤锚点
4     version u8 =1    演进兼容
5     flags u8         保留（位0：传输类型标记）
6     client_id[8]     SHA-256(客户端Ed25519公钥)前8字节，明文，供服务端选key
14    eph_pk[32]       客户端临时 X25519 公钥
46    nonce[24]        XChaCha20-Poly1305 nonce
70    ciphertext[..]   内层消息 AEAD 密文（AAD = 偏移0..69 头部字节）
..    tag[16]          AEAD 认证标签（密文尾部）
..    sig[64]          Ed25519 签名，覆盖 magic..tag 全部前置字节
```

内层明文（定长二进制编码，不用 CBOR，保持简单可审计）：

```
ts u64（unix秒） | req_nonce[16] | port_count u8 | ports [u16; ≤8] | ttl u32（秒）
```

最小包长 = 头部 154 字节 + 内层最小明文（约 30 字节）；eBPF 以 `MAX_SPA_PKT=512` 为上界校验。

### 3.2 密码学

- **机密性**：客户端生成临时 X25519 密钥对，`shared = X25519(eph_sk, server_pk)` → HKDF-SHA256(shared, salt=nonce) → XChaCha20-Poly1305 密钥；AEAD 加密内层消息，AAD 绑定全部头部字节（防头部篡改/降级）。
- **认证**：客户端长期 Ed25519 私钥对 magic..tag 签名；服务端按 client_id 查注册公钥验签。
- **服务端密钥材料**：静态 X25519 密钥对（私钥 0600 文件）+ 客户端 Ed25519 公钥表（配置文件，绑定策略）。
- 加密与签名并存的理由：签名解决"谁"，加密解决"藏"（端口/TTL/时间等元数据不对窃听者暴露）。

### 3.3 验证管线（成本递增排序，DoS 韧性）

1. eBPF：magic/长度/版本匹配 + per-IP 令牌桶限速（§4）；
2. 验签（Ed25519）——失败即弃，不进解密路径（继承 fwknop HMAC-first 思想）；
3. 解密（X25519+AEAD）；
4. 防重放：ts 时间窗 ±300s + req_nonce 查 Go 侧 TTL map（nonce 在密文内层，eBPF 不可见，天然应在用户态）；TCP SYN 重传由 nonce 去重吸收；
5. 策略校验：请求端口 ⊆ 该 client_id 允许集，TTL ≤ 策略上限；
6. 通过 → 写 allowlist map；每步拒绝均产生带 `reject_reason` 的审计事件。

---

## 4. eBPF 数据面（bpf/knok_ingress.c）

单程序、TC/TCX 两种 attach 方式，处理顺序按成本短路：

```
hook(skb):
  1. 解析 eth/ip/l4（非 IP、分片 → TC_ACT_OK 放行，不干扰正常流量）
  2. allowlist 查询 key={srcIP, dstPort}：
       命中且 expiry_ns > bpf_ktime_get_ns() → skb->mark = 0x4B4E4F4B; TC_ACT_OK
       （已授权流量全程内核内完成，不上送；过期条目惰性删除）
  3. SPA 候选匹配：
       UDP: dport == cfg.spa_port 且 payload 前4字节 == "KNOK" 且 len ∈ [最小包长, 512]
       TCP: dport ∈ cfg.protected_ports 且 SYN 且 payload 前4字节 == "KNOK"
  4. 限速：per-srcIP 令牌桶（rate_buckets map），超限 → 计数 + 丢弃
       （TCP SYN 例外：只计数不丢——丢 SYN 引发对端重传风暴，交给 nftables drop）
  5. ringbuf 上送 spa_event（reserve+submit）：
       { ts u64; ifindex u32; transport u8; ipver u8; srcIP[16];
         srcPort u16; dstPort u16; payload_len u16; payload[512] }
  6. 兜底 TC_ACT_OK —— knok 数据面永不主动丢业务流量，drop 语义归 nftables 表
```

**Map 布局**（全部 pinned `/sys/fs/bpf/knok/`，重启不丢授权状态）：

| map | 类型 | key → value | 用途 |
|---|---|---|---|
| allowlist | LRU_HASH | {ip[16], port u16} → expiry_ns u64 | 授权状态（v4 用 v4-mapped v6 统一 16 字节） |
| rate_buckets | LRU_HASH | ip[16] → {tokens u32, last_ns u64} | 限速 |
| spa_events | RINGBUF | —（512KB，满则丢并计数） | 候选包上送 |
| cfg | ARRAY | idx → 配置值 | spa_port、protected_ports、限速参数（用户态写入） |
| stats | ARRAY | idx → u64 | 命中/过期/限速丢/ringbuf满/上送计数 |

防重放 nonce 缓存不在 BPF（见 §3.3 第 4 步），为 Go 侧 TTL map。

---

## 5. 平台适配器（internal/platform，linux only）

### 5.1 AttachBackend（TCX / clsact TC）

```go
type AttachBackend interface {
    Attach(ifindex int, prog *ebpf.Program, maps map[string]*ebpf.Map) (Handle, error)
    Detach(h Handle) error
    List() ([]Handle, error) // 启动对账，清理崩溃残留
}
```

启动 `DetectBackend()`：尝试 `link.AttachTCX`（≥6.6，bpf_link 进程退出自动清理）→ 失败降级 clsact：确保 qdisc 存在 + netlink `FilterAdd`（filter 名固定 `knok`、pref 固定 42000），`List()` 对账残留并替换。探测结果写日志 + `knok_backend` 指标。

### 5.2 NicManager 与 reconcile

reconcile 是平台逻辑，归 Layer 2（platform/netlink）；core 只消费：

```go
type NicManager interface {
    Desired() <-chan []NicState // 链路/路由变化时推送期望接口集
}
```

组装根中 `attachSupervisor` goroutine 消费 `Desired()` 做 Attach/Detach 对账。接口匹配规则（auto/explicit/exclude）由组装根解释配置后传入——core 与 platform 均不解析配置。auto = 默认路由接口 + UP 的非虚拟物理口，排除 lo/容器/网桥。热插拔（RTM_NEWLINK/DELLINK）触发增量 reconcile。

### 5.3 Firewall（platform/nftables）

声明式幂等同步：`EnsureProtectedPorts(ports)` 用 google/nftables 全量 diff 替换 `inet knok` 表。

**nftables 语义关键点**：`accept` 非终局（继续走用户链），`drop` 是终局。故契约设计为：

- `inet knok` 表 input 链 priority -200（先于用户 filter 链）；
- 受保护端口：无 mark → **drop（终局）**，用户防火墙根本看不到未授权包；
- 有 mark(0x4B4E4F4B) → accept，进入协议栈（用户链仍可叠加自身策略）；
- 文档要求用户不要在自家防火墙对受保护端口写放行规则（避免双重语义）。

knokd 正常退出**保留**该表（fail-closed，崩溃不敞门）；`knokd --uninstall` 显式拆除。

### 5.4 Allowlist（platform/ebpf）

实现 core 的 `Allowlist` 接口：Grant=map put（expiry=now+ttl，bpf_ktime 单调时钟换算）、Revoke=delete、List=iterate。启动时从 pinned map 恢复视图；`admin_allow` 静态条目以 expiry=u64max 写入。

---

## 6. knokd 守护进程（cmd/knokd 组装根）

启动序列（**顺序不变量**）：

```
1. 加载配置 + 密钥材料（失败→退出，不动任何内核状态）
2. open pinned maps / 创建并 pin（含从上次运行恢复 allowlist）
3. DetectBackend + attachSupervisor 完成全部目标网卡 attach
4. ringbuf 消费者 + 验证管线启动（授权通路就绪）
5. 写入 admin_allow 静态放行条目（逃生通道）
6. 最后：EnsureProtectedPorts 安装 nftables drop 规则
   —— 任何前置步骤失败则不装防火墙，fail-open 并大声报错
```

主循环组件：验证管线（§3.3）、审计输出（JSON lines → stdout/journald + AuditSink 可扩展 webhook）、Prometheus `/metrics`（验证计数、reject_reason 分布、ringbuf 丢弃、allowlist 规模、backend 类型）、SIGHUP 热重载（重读 clients/策略；被吊销 client 的 allowlist 条目即刻清除）。

配置 `/etc/knok/knokd.toml`：

```toml
[listen]
spa_udp_port = 4242
protected_ports = [22]          # TCP SYN 模式监听 + nftables 隐藏
[interfaces]
mode = "auto"                   # auto | explicit | exclude
exclude = ["lo", "docker*", "veth*", "br-*"]
[keys]
x25519_private = "file:/etc/knok/server-x25519.key"   # 0600
[safety]
admin_allow = []                # 永久放行的管理网段（逃生通道）
[[clients]]
ed25519_public = "MCowBQ..."    # client_id 自动推导
allow_ports = [22]
max_ttl = "30m"
[pin]
dir = "/sys/fs/bpf/knok"
[ratelimit]
per_ip_burst = 5
per_ip_rate = "1/10s"
```

---

## 7. 客户端 knok（cmd/knok）

命令面：

```
knok keygen [--server]              # Ed25519 客户端密钥对 / 服务端 X25519 密钥对
knok auth <server名> [--port 22] [--ttl 60s] [--exec "ssh user@host"]
knok enroll --via ssh user@host     # 本地公钥 → SSH 追加远端配置 → 触发 SIGHUP
knok status                         # 本地密钥/配置自检（不发真实包）
```

Transport 抽象（两实现）：

- `udpTransport`：`net.Dial("udp")`，零权限全平台，默认推荐；
- `rawSynTransport`：raw socket 构造 SYN+载荷（Linux CAP_NET_RAW/root；macOS root；Windows 一期不支持）；不可用时报清晰错误并提示改用 UDP。

重试语义：每次重试全新 nonce/ts（包独立有效），默认 3 次、指数退避 200ms→800ms→3.2s；`--exec` 首包后等 300ms 执行。配置 `~/.config/knok/config.toml`（server 别名 → host、服务端 X25519 公钥、本地私钥路径）。

无响应设计：服务端不回包（静默是特性），成败以 `--exec` 实际连接结果判断。

---

## 8. 错误处理与防锁死

1. 启动顺序不变量（§6）：授权通路就绪前绝不装防火墙。
2. `admin_allow` 逃生通道：永久 allowlist 条目；文档强调保留云控制台。
3. 崩溃行为：daemon 死 → eBPF 仍 attach、pinned map 授权继续有效（已进门者不掉线）、nftables 表保留（fail-closed）、新授权暂停；systemd `Restart=always`。
4. ringbuf 溢出：stats 计数 + warn 日志 + 指标，不静默。
5. 时钟偏移：`reject_reason=clock_skew` 单独归类；客户端 auth 前可选做本地时间合理性检查。
6. `--uninstall` 显式拆墙；正常退出保留表。

---

## 9. 测试策略

| 层 | 手段 | 环境 |
|---|---|---|
| protocol | JSON 固化测试向量（供第三方实现对照）+ 表驱动单测 + go-fuzz 打解析器 | macOS |
| core | 内存适配器 + fakeClock；管线全分支表驱动（过期/错签/重放/越权/skew） | macOS |
| platform | `//go:build integration`：netns 内 attach/detach、残留清理、veth 热插拔、nftables 幂等 | VPS |
| E2E | 验收脚本：真实 SSH 端口全链路 + TTL 到期断连 + 崩溃重启授权保持 | VPS |
| 架构守护 | CI 断言 internal/core import 不含 ebpf/netlink/nftables | CI |

---

## 10. 实施里程碑（垂直切片）

- **M1 骨架**：仓库脚手架 + bpf2go 工具链 + TCX attach + magic 过滤 + ringbuf + Go 消费者日志（VPS 验证最高风险内核集成）
- **M2 薄端到端**：UDP-only + 静态共享密钥（临时简化，不进 README）+ allowlist + mark + inet knok 表 + 最小客户端 → 敲门→SSH 通→TTL 关闭（首个可演示里程碑）
- **M3 协议正式化**：完整线格式 + AEAD/Ed25519/防重放 + 策略模型 + 审计 + core 分层归位
- **M4 TCP SYN 传输**：BPF 匹配扩展 + rawSynTransport
- **M5 运维面**：keygen/enroll/热重载 + NicManager reconcile + clsact 兜底 + pinned 崩溃恢复
- **M6 加固收尾**：eBPF 限速 + admin_allow + Prometheus + 文档 + v0.1.0

---

## 11. 风险与开放问题

| 风险 | 缓解 |
|---|---|
| TCP SYN 携带载荷的中间设备兼容性（部分云安全组/防火墙丢带载荷 SYN） | 文档注明；UDP 模式为默认推荐路径 |
| 用户防火墙对受保护端口另有规则导致语义冲突 | 文档契约 + knokd 启动时检测冲突并 warn |
| VPS 虚拟网卡 XDP/TCX 行为差异 | 首发 TCX ingress（虚拟网卡普遍支持），集成测试覆盖 |
| 静态密钥简化版（M2）泄漏进 main 历史 | M2 密钥仅测试用常量，M3 立即替换，README 不提及 |
| nftables priority 与用户已有高优先级链冲突 | -200 足够靠前；启动时 dump 钩子链检测并 warn |

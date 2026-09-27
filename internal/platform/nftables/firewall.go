// Package nftables 实现 ports.Firewall：管理 knok 独占的 inet knok 表。
// 契约：受保护端口无 mark 一律 drop（终局裁决）；带 KNOK mark 的包 accept
// 后继续走用户防火墙链。knok 永不修改用户自己的表。
//
// 构建切分（见本任务 Ruling 7）：RenderRuleset 与 Firewall 类型是纯逻辑，
// 放在本无 tag 文件中，任意平台可编译可单测；真正 fork/exec nft 的执行路径
// 只在 Linux 上存在（firewall_linux.go），非 Linux 构建由 firewall_other.go
// 提供同签名桩并返回 "nftables: linux only"。渲染语义两平台完全一致。
//
// 设计说明（对 spec §5.3 的实现细化）：表同步是低频控制面操作（仅启动/配置
// 变更时），用系统 nft -f - 声明式整表替换（add table + flush table + 定义），
// 替代 google/nftables 库的逐表达式构造——更少的依赖面、规则文本可审计。
package nftables

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/zhouyu0615/knok/internal/platform/mark"
)

// Firewall 是 ports.Firewall 的 nftables 实现。它无状态：每次调用都做整表
// 声明式替换（幂等），不缓存任何东西。
type Firewall struct{}

func New() *Firewall { return &Firewall{} }

// RenderRuleset 渲染 knok 独占表的完整 nft 脚本（纯函数，跨平台可测）。
//
// 幂等性来自 "add table" + "flush table" 组合：表不存在时 add 建之，表已存在
// 时 add 成功且 flush 清空其内容，随后写入本次定义——重复应用同一配置结果相同。
//
// 规则顺序即语义：priority -200 使本链先于用户 filter 链执行；accept 非终局，
// 但必须排在 drop 之前——marked 包命中 accept 后继续走用户的链（用户仍可叠加
// 自己的策略）；无 mark 的包落到 drop（终局），用户防火墙根本看不到未授权包。
// SPA 端口同样 drop 以保持静默（不泄漏 ICMP port unreachable）。
//
// 受保护端口的 drop **两种协议都要渲染**（Ruling 26）：spec 的"无 mark 即 drop"
// 契约里没有协议限定词，数据面也对 tcp/udp 都打 mark。只写 tcp 会让一个受保护的
// UDP 端口对所有人大开——而命令与日志都显示成功，是最难发现的那种静默失败。
//
// 匹配的 mark 取自 internal/platform/mark（Ruling 22）：它与 eBPF 数据面写进
// skb->mark 的值是同一份常量，两侧各自硬编码会静默漂移——mark 对不上时
// 已授权流量会落到下面的 drop 规则被丢弃。
func RenderRuleset(protected []uint16, spaPort uint16) string {
	ports := dedupeSorted(protected)
	var b strings.Builder
	b.WriteString("add table inet knok\n")
	b.WriteString("flush table inet knok\n")
	b.WriteString("table inet knok {\n")
	b.WriteString("  chain input {\n")
	b.WriteString("    type filter hook input priority -200; policy accept;\n")
	fmt.Fprintf(&b, "    meta mark %s accept\n", mark.Hex)
	if len(ports) > 0 {
		strs := make([]string, len(ports))
		for i, p := range ports {
			strs[i] = strconv.Itoa(int(p))
		}
		// 端口集合渲染一次、协议各写一行：nft 的集合字面量不支持"按协议展开"，
		// 而把 tcp/udp 合成一条 inet 规则（`meta l4proto { tcp, udp } th dport {...}`）
		// 在可读性与后续审计上都更差——两行是这里最直白的表达。
		join := strings.Join(strs, ", ")
		fmt.Fprintf(&b, "    tcp dport { %s } drop\n", join)
		fmt.Fprintf(&b, "    udp dport { %s } drop\n", join)
	}
	fmt.Fprintf(&b, "    udp dport %d drop\n", spaPort) // SPA 端口静默（不回 ICMP）
	b.WriteString("  }\n")
	b.WriteString("}\n")
	return b.String()
}

// dedupeSorted 返回去重且升序的副本。不修改入参（调用方的切片可能被复用）。
func dedupeSorted(protected []uint16) []uint16 {
	out := append([]uint16(nil), protected...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	n := 0
	for i, p := range out {
		if i == 0 || p != out[n-1] {
			out[n] = p
			n++
		}
	}
	return out[:n]
}

// Package mark 持有 KNOK meta mark 的唯一权威定义。
//
// 两个消费者必须引用同一份值：
//
//   - eBPF 数据面（internal/platform/ebpf 的 MarkKNOK，对应 C 侧
//     bpf/knok_ingress.c 的 #define MARK_KNOK）：命中 allowlist 时把 mark
//     写进 skb->mark；
//   - nftables 防火墙（internal/platform/nftables 的规则渲染，走 Hex）：
//     渲染 `meta mark <Hex> accept`，让已授权流量穿过 knok 表。
//
// 任何一侧自带字面量都会产生静默漂移：mark 数值不一致时，eBPF 打的标
// 命中不了 accept 规则，已授权流量会落到 drop 规则被丢弃（Ruling 22）。
//
// 本包刻意无依赖、无 build tag：macOS 与 Linux 都必须能编译。
package mark

// Mark 是数据面写入 skb->mark（主机字节序）的值：大端顺序的 ASCII "KNOK"，
// spec §5.3 冻结为 0x4B4E4F4B。
const Mark uint32 = 0x4B4E4F4B

// Hex 是 Mark 的 nft 规则文本形式（小写十六进制，nft 只接受数字字面量）。
// 必须等于 fmt.Sprintf("0x%08x", Mark)；由 mark_test.go 钉住。
const Hex = "0x4b4e4f4b"

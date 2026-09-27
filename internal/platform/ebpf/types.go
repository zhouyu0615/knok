// Package ebpfplat 提供 knok eBPF 数据面的 Go 侧适配。
//
// 本文件（无 build tag、无 cilium/ebpf 依赖）只放数据面两侧共享的布局常量：
// 它在 macOS 上可编译可单测，而真正调用 cilium/ebpf 的代码带 //go:build linux。
package ebpfplat

import "github.com/zhouyu0615/knok/internal/platform/mark"

// spa_event 在 BPF C 与 Go 间的字节偏移（little-endian）。这些偏移是
// bpf/knok_ingress.c 里 struct spa_event 的内存布局的镜像，**两侧必须同时修改**：
//
//	struct spa_event { u64 ts_ns; u32 ifindex; u8 ipver; u8 pad[3];
//	                   u8 src_ip[16]; u16 src_port; u16 dst_port;
//	                   u16 payload_len; u8 payload[512]; }
//
// 只改一侧不会编译失败——ringbuf 事件会被静默解析成垃圾（或越界读取）。
// types_test.go 逐项钉住这些数值，任何一侧的改动都必须是有意的。
const (
	EvOffTS      = 0                  // u64 ts_ns（bpf_ktime_get_ns 单调时钟，纳秒）
	EvOffIfindex = 8                  // u32 ifindex
	EvOffIPVer   = 12                 // u8 ipver：4 或 6（其后 pad[3] 未使用）
	EvOffSrcIP   = 16                 // u8 src_ip[16]：IPv4 为 v4-mapped IPv6
	EvOffSrcPort = 32                 // u16 主机序
	EvOffDstPort = 34                 // u16 主机序（= SPA 端口）
	EvOffPLen    = 36                 // u16 实际载荷长度（≤ MaxSPAPkt）
	EvOffPayload = 38                 // u8 payload[MaxSPAPkt]，前 payload_len 字节有效
	EvSize       = 38 + MaxSPAPkt + 2 // 尾部对齐到 8（552）：ringbuf 保留区大小
)

// MarkKNOK 是数据面写入的 skb->mark，来自唯一权威定义 internal/platform/mark
// （与 nftables 渲染的 meta mark 是同一个值）；C 侧对应 #define MARK_KNOK。
const MarkKNOK = mark.Mark

// MaxSPAPkt 是 ringbuf 事件里载荷缓冲的上限，也是 C 侧 #define MAX_SPA_PKT。
const MaxSPAPkt = 512

// stats 槽位（与 C 侧 #define 一致；顺序即 ARRAY 索引，不可重排）
const (
	StTotal       = 0 // 进入程序且已通过链路层校验的包
	StAllowHit    = 1 // allowlist 命中且未过期（已打 mark）
	StAllowExpiry = 2 // allowlist 命中但已过期（已删除）
	StCandidate   = 3 // UDP SPA 候选已提交到 ringbuf
	StRateDrop    = 4 // M6 启用（M2 保留未用）
	StRingbufDrop = 5 // ringbuf 保留失败（丢弃）
	StSlots       = 6 // stats 数组长度
)

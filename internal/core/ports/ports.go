// Package ports 定义 core 层依赖的全部接口（六边形架构的"端口"）。
// 本包永不 import 任何平台库。
package ports

import (
	"net/netip"
	"time"
)

// CandidatePacket 是经 eBPF 特征过滤后上送的 SPA 候选包。
type CandidatePacket struct {
	SrcIP      netip.Addr
	DstPort    uint16
	IfIndex    int
	Payload    []byte
	ReceivedAt time.Time
}

// Decision 是验证管线的输出。RejectReason 取值：
// "" | bad_packet | auth_failed | clock_skew | replay | policy | grant_failed
//
// grant_failed 契约：包已通过全部验证，但把某个端口写入数据面失败。此时 Allowed 被置为
// false，Ports 是**本次评估中实际已成功授权的端口子集**（可能为空；为空时是非 nil 空切片），
// 且失败端口之后不再尝试授权任何端口。已成功的授权不会被回滚——它可能来自同一客户端早先的
// 包，回滚会误伤那一条。其余 reject 原因下 Ports 无意义。
type Decision struct {
	Allowed      bool
	SrcIP        netip.Addr
	Ports        []uint16
	TTL          time.Duration
	RejectReason string
}

// Entry 是 allowlist 中的一条授权。
type Entry struct {
	IP        netip.Addr
	Port      uint16
	ExpiresAt time.Time
	Forever   bool
}

type PacketSource interface {
	Packets() <-chan CandidatePacket
	Close() error
}

// Allowlist 管理 (IP, port) 授权。
//
// 过期约定（所有实现必须一致）：一条授权严格存活到它的过期时刻之前——即带 TTL 的
// 条目仅在 now < ExpiresAt 时算存活，当 now == ExpiresAt 时即视为已过期；
// Forever 条目不参与该判断，永不失效。
// 该约定与 eBPF 数据面的判断（*expiry > bpf_ktime_get_ns()）一致。
type Allowlist interface {
	Grant(ip netip.Addr, port uint16, ttl time.Duration) error
	GrantForever(ip netip.Addr, port uint16) error
	Revoke(ip netip.Addr, port uint16) error
	List() ([]Entry, error)
}

type Firewall interface {
	EnsureProtectedPorts(protectedPorts []uint16, spaUDPPort uint16) error
	Uninstall() error
}

type Clock interface {
	Now() time.Time
}

type AuditSink interface {
	Emit(Decision, CandidatePacket)
}

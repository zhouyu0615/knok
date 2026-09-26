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
// "" | bad_packet | auth_failed | clock_skew | replay | policy
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

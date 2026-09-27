//go:build linux

package ebpfplat

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/zhouyu0615/knok/internal/core/ports"
)

// RingbufSource 是 ports.PacketSource 的 eBPF 实现：消费 spa_events ringbuf，
// 把每个样本解析成 ports.CandidatePacket。
//
// 两个刻意的语义（都有消费方依赖，改动前先看 Authenticator.Run）：
//
//   - Packets 永远返回同一个 channel（ports.PacketSource 的契约）。Authenticator
//     每轮循环都会重新调用 Packets()，返回新 channel 会让上一轮读到的事件连同
//     旧 channel 一起被丢弃——表现是候选包随机丢失，而不是报错。
//   - Close 不关闭该 channel：消费方靠 ctx 退出。关闭 channel 会让后续读取立刻
//     返回零值包，被误判成一个 SrcIP 为 "::" 的坏包（而 Authenticator 把"通道已
//     关闭"当作"数据面已收摊"）。
//
// 消费方过慢时**丢弃而不阻塞**：阻塞 reader 会把内核 ringbuf 顶满，进而让内核侧
// 的 bpf_ringbuf_reserve 失败（stats 的 StRingbufDrop）——那是在资源更紧的内核
// 里丢包，比在这里丢更糟。丢弃条数记在 Dropped。
type RingbufSource struct {
	reader    *ringbuf.Reader
	out       chan ports.CandidatePacket
	closeOnce sync.Once
	closeErr  error

	// Dropped 统计"内核已交上来、但消费方来不及读"（channel 满）而主动丢弃的
	// 条数。它只反映 Go 侧消费太慢；内核侧保留失败的计数在 stats 的
	// StRingbufDrop，两者不要混为一谈。
	Dropped atomic.Uint64
}

// NewRingbufSource 在 m（spa_events map）上开一个 reader，并起 goroutine 持续
// 消费。buf 是 Go 侧 channel 的容量：0 表示不缓冲（每个事件都要求消费方当场
// 在等，否则丢弃），负数是无效参数。
func NewRingbufSource(m *ebpf.Map, buf int) (*RingbufSource, error) {
	if buf < 0 {
		return nil, fmt.Errorf("ringbuf consumer buffer %d must be >= 0", buf)
	}
	r, err := ringbuf.NewReader(m)
	if err != nil {
		return nil, fmt.Errorf("ringbuf reader: %w", err)
	}
	s := &RingbufSource{reader: r, out: make(chan ports.CandidatePacket, buf)}
	go s.loop()
	return s, nil
}

// Packets 返回候选包通道：**每次调用返回同一个 channel**（见类型注释）。
func (s *RingbufSource) Packets() <-chan ports.CandidatePacket { return s.out }

// Close 关闭 reader（解除 loop 的阻塞并释放 epoll/fd）。幂等：重复调用返回
// 同一个结果；out 不关闭（见类型注释）。
func (s *RingbufSource) Close() error {
	s.closeOnce.Do(func() { s.closeErr = s.reader.Close() })
	return s.closeErr
}

// loop 持续把 ringbuf 事件搬进 out，直到 reader 关闭。
//
// Read 的错误分两类：ErrClosed 是 Close 的正常结果（退出）；其余是 epoll/read
// 的瞬时或永久失败——不退出（否则数据面静默失联），但也不忙等（永久失败会把
// 一个核烧在 100% CPU 上），退避 1ms 后重试。
func (s *RingbufSource) loop() {
	for {
		rec, err := s.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			time.Sleep(time.Millisecond)
			continue
		}
		pkt, ok := parseEvent(rec.RawSample)
		if !ok {
			continue
		}
		select {
		case s.out <- pkt:
		default:
			s.Dropped.Add(1)
		}
	}
}

// parseEvent 把原始 ringbuf 样本解析成 CandidatePacket；ok=false 表示样本违反
// 布局约束（头部不完整、payload_len 为 0 或越界），调用方丢弃即可。
//
// 样本布局是两侧共享的 ABI（见 types.go 的 EvOff* 注释）：C 侧正常提交的事件
// 永远不会走到 ok=false——出现即意味着 C 与 Go 的布局漂移了。此时宁可丢弃，
// 也不要把错位的字节解析成"看起来合法"的包（错误校验/错误授权）。
func parseEvent(d []byte) (ports.CandidatePacket, bool) {
	if len(d) < EvOffPayload {
		return ports.CandidatePacket{}, false
	}
	plen := int(binary.LittleEndian.Uint16(d[EvOffPLen:]))
	if plen == 0 || plen > MaxSPAPkt || len(d) < EvOffPayload+plen {
		return ports.CandidatePacket{}, false
	}

	// C 侧 IPv4 也写 16 字节（v4-mapped），ipver 决定用哪一种解码：
	// IPv4 的 4 字节在 src_ip[12:16]，前 12 字节是 ::ffff 前缀。
	var ip netip.Addr
	if d[EvOffIPVer] == 4 {
		ip = netip.AddrFrom4([4]byte(d[EvOffSrcIP+12 : EvOffSrcIP+16]))
	} else {
		ip = netip.AddrFrom16([16]byte(d[EvOffSrcIP : EvOffSrcIP+16]))
	}

	payload := make([]byte, plen)
	copy(payload, d[EvOffPayload:EvOffPayload+plen])

	return ports.CandidatePacket{
		SrcIP:   ip,
		DstPort: binary.LittleEndian.Uint16(d[EvOffDstPort:]),
		IfIndex: int(binary.LittleEndian.Uint32(d[EvOffIfindex:])),
		Payload: payload,
		// 事件自带的 ts_ns 是单调时钟（bpf_ktime_get_ns），换算不回墙钟；
		// ReceivedAt 的用途是审计与日志，取消费时刻更直观。
		ReceivedAt: time.Now(),
	}, true
}

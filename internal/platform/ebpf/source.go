//go:build linux

package ebpfplat

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/zhouyu0615/knok/internal/core/ports"
)

// warnInterval 是 ringbuf 异常日志的限流间隔（见 warnRateLimited）。
const warnInterval = 5 * time.Second

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

	// ReadErrors 统计 ringbuf 读取失败的次数（ErrClosed 之外的错误）；Malformed
	// 统计"样本违反布局约束、被 parseEvent 拒绝"的次数。两者都只发生在 Go 侧。
	//
	// 它们的存在理由：C↔Go 契约漂移在**运行期**的唯一信号就是这两个数（静态守护
	// 在 contract_test.go）。在此之前 reader 错误与解析失败都被静默 continue 掉，
	// 于是"数据面在交事件、Go 侧一条都没收到"这个状态在日志与指标里都不存在——
	// 只看内核计数器的话它与"没有流量"完全一样。
	ReadErrors atomic.Uint64
	Malformed  atomic.Uint64

	// lastWarn 是上一次 warn 的 unix 纳秒（限流，见 warnRateLimited）。
	lastWarn atomic.Int64
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
// 一个核烧在 100% CPU 上），退避 1ms 后重试。重试次数记在 ReadErrors。
func (s *RingbufSource) loop() {
	for {
		rec, err := s.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			s.ReadErrors.Add(1)
			s.warnRateLimited("ringbuf read failed; retrying (candidate packets may be dropped)",
				"err", err, "read_errors", s.ReadErrors.Load())
			time.Sleep(time.Millisecond)
			continue
		}
		pkt, ok := parseEvent(rec.RawSample)
		if !ok {
			// 布局漂移（或内核/生成物版本不一致）的运行期信号：契约由
			// contract_test.go 静态钉住，这里是它漏网时的兜底。
			s.Malformed.Add(1)
			s.warnRateLimited("ringbuf sample rejected: C/Go layout drift? sample dropped",
				"len", len(rec.RawSample), "malformed", s.Malformed.Load())
			continue
		}
		select {
		case s.out <- pkt:
		default:
			s.Dropped.Add(1)
		}
	}
}

// warnRateLimited 以"至少间隔 warnInterval"的频率打一条 warn。
//
// 限流是必需的：reader 错误与漂移样本会按每次循环的频率持续发生，不限流会把日志
// 刷满、把真正重要的信息埋掉。计数在指标里始终精确，日志只需"出现过"这个信号，
// 所以两条异常共用同一个时限（谁先到谁说话）。CompareAndSwap 保证并发时只有一条
// 日志落地（loop 是单 goroutine，但 Close/未来调用方不受此假设约束）。
func (s *RingbufSource) warnRateLimited(msg string, args ...any) {
	now := time.Now().UnixNano()
	last := s.lastWarn.Load()
	if now-last < int64(warnInterval) {
		return
	}
	if !s.lastWarn.CompareAndSwap(last, now) {
		return
	}
	slog.Warn(msg, args...)
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

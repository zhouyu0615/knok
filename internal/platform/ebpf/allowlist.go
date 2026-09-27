//go:build linux

package ebpfplat

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/zhouyu0615/knok/internal/core/ports"
	"golang.org/x/sys/unix"
)

// allowKeySize 是 C 侧 struct allow_key 的字节数：
//
//	struct allow_key { __u8 ip[16]; __u16 port; __u16 pad; };
const allowKeySize = 20

// MapAllowlist 是 ports.Allowlist 的 eBPF 实现：直接读写数据面的 LRU_HASH map。
// 授权写进 map 后由内核在 TC ingress 上完成匹配与打标（skb->mark），命中路径
// 完全不经过 Go——这正是 knok 相对 fwknop "每个 SYN 都要过用户态" 的核心差别。
//
// 过期时间用 CLOCK_MONOTONIC 纳秒编码（与 C 侧 bpf_ktime_get_ns 同源），因此
// 与墙钟调整（NTP 跳变、时区、挂起恢复）无关；List 需要墙钟时间时才用 clock
// 把"剩余单调时间"换算成 ExpiresAt。
//
// 并发：*ebpf.Map 的 Update/Delete/Iterate 都是系统调用，本身线程安全（内核
// map 自带锁）；本类型不持有额外可变状态，可被多个 goroutine 直接共用。
type MapAllowlist struct {
	m     *ebpf.Map
	clock ports.Clock
}

// NewMapAllowlist 包装数据面的 allowlist map（objs.Allowlist）。
// clock 只用于 List 把剩余 TTL 换算成墙钟的 ExpiresAt。
func NewMapAllowlist(m *ebpf.Map, clock ports.Clock) *MapAllowlist {
	return &MapAllowlist{m: m, clock: clock}
}

// allowKey 按 C 侧 struct allow_key 的布局编码 (ip, port)：
//
//	__u8 ip[16];  // IPv4 以 v4-mapped IPv6（::ffff:a.b.c.d）存储
//	__u16 port;   // 主机序
//	__u16 pad;    // 0
//
// 必须与 bpf/knok_ingress.c 里 key 的构造逐字节一致：任何一字节不同都会让授权
// 永远匹配不上（表现为"客户端敲了门，端口却没开"，而不是报错）。
func allowKey(ip netip.Addr, port uint16) [allowKeySize]byte {
	var k [allowKeySize]byte
	if ip.Is4() || ip.Is4In6() {
		// v4-mapped：字节 0..9 为 0，10..11 为 0xffff，12..15 为 IPv4。
		k[10], k[11] = 0xff, 0xff
		b := ip.As4()
		copy(k[12:16], b[:])
	} else {
		b := ip.As16()
		copy(k[0:16], b[:])
	}
	binary.NativeEndian.PutUint16(k[16:18], port)
	return k
}

// isV4MappedKey 判定 key 的 16 字节地址是否为 v4-mapped 形式（::ffff:a.b.c.d），
// 即 C 侧写 IPv4 的形态。
//
// 不能只看 k[10]==0xff && k[11]==0xff：合法 IPv6 地址的第 6 组也可能恰好是
// ffff（如 2001:db8::ffff:1:2），只看两个字节会把它误解码成 IPv4。完整判据是
// IN6_IS_ADDR_V4_MAPPED：前 10 字节全零 **且** 10..11 为 0xffff。
func isV4MappedKey(k [allowKeySize]byte) bool {
	for i := 0; i < 10; i++ {
		if k[i] != 0 {
			return false
		}
	}
	return k[10] == 0xff && k[11] == 0xff
}

// addrFromKey 是 allowKey 的逆运算（List 用）。
//
// IPv4 解码回 4 字节形式（netip.AddrFrom4），与调用方当初 Grant 的写法一致：
// C 侧不区分 4 字节与 v4-mapped 的 16 字节（两者的 key 相同），而 4 字节形式
// 是更常见的那一种。
func addrFromKey(k [allowKeySize]byte) netip.Addr {
	if isV4MappedKey(k) {
		return netip.AddrFrom4([4]byte{k[12], k[13], k[14], k[15]})
	}
	return netip.AddrFrom16([16]byte(k[0:16]))
}

// monoNowNs 读 CLOCK_MONOTONIC 纳秒——与 C 侧 bpf_ktime_get_ns 是同一个时钟
// （都是自启动以来的单调时间），所以 map 里存的值可以直接和内核里的比较。
//
// 只有传错 clockid 才会失败（EINVAL），此时返回 0：0 在任何比较下都是"已过期"，
// 是唯一不会误放行的降级值。
func monoNowNs() uint64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0
	}
	return uint64(ts.Nano())
}

// expiredForever 是 GrantForever 写入的过期时刻：uint64 的极大值。内核用
// *expiry > bpf_ktime_get_ns() 判断，而单调时钟纳秒要到 ~584 年才可能追上它，
// 等价于"永不失效"（也因此在 List 里必须是特例，不能按 TTL 反算 ExpiresAt）。
const expiredForever = ^uint64(0)

// Grant 写入 (ip, port) → 过期时刻（单调纳秒）。同 key 重复授权是覆盖（幂等），
// 这既是"续期"的实现方式，也让 Authenticator 的重复投递不会出错。
//
// ttl <= 0 一律写成 0（立刻过期），而不是让负数在 uint64 加法里回绕成 ~584 年：
// 一次误传的负 TTL 不该变成永久放行。0 与 ports.Allowlist 的严格约定一致
// （now < expiry 才算存活：expiry=0 在任何时刻都已过期）。
func (a *MapAllowlist) Grant(ip netip.Addr, port uint16, ttl time.Duration) error {
	k := allowKey(ip, port)
	v := uint64(0)
	if ns := ttl.Nanoseconds(); ns > 0 {
		v = monoNowNs() + uint64(ns)
	}
	if err := a.m.Update(unsafe.Pointer(&k[0]), unsafe.Pointer(&v), ebpf.UpdateAny); err != nil {
		return err
	}
	return nil
}

// GrantForever 写入永不失效的授权（逃生通道：admin_allow，Task 9 用它给管理
// 地址永久放行；也是保护端口自身可达性的兜底）。
func (a *MapAllowlist) GrantForever(ip netip.Addr, port uint16) error {
	k := allowKey(ip, port)
	v := expiredForever
	if err := a.m.Update(unsafe.Pointer(&k[0]), unsafe.Pointer(&v), ebpf.UpdateAny); err != nil {
		return err
	}
	return nil
}

// Revoke 删除授权，幂等：key 不存在时返回 nil（删掉一个本就失效的授权与"删成功"
// 对调用方结果相同，而把 ErrKeyNotExist 当失败只会让"反复撤销"报假错）。
func (a *MapAllowlist) Revoke(ip netip.Addr, port uint16) error {
	k := allowKey(ip, port)
	if err := a.m.Delete(unsafe.Pointer(&k[0])); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}
	return nil
}

// List 返回当前**存活**的授权（严格约定：now < expiry 才算存活，now == expiry
// 即已过期）。
//
// 过期条目在这里只是被跳过，不顺手删除：LRU_HASH 上边迭代边删除会漏掉条目
// （内核文档明确不建议），而清理并不需要 List 来做——真正命中的过期 key 由
// 数据面在匹配时删除（并计入 ST_ALLOW_EXPIRY），没被命中的过期 key 会被 LRU
// 自然淘汰。
//
// 返回顺序是 LRU_HASH 的迭代顺序（无序）。空结果返回非 nil 空切片。
func (a *MapAllowlist) List() ([]ports.Entry, error) {
	now := monoNowNs()
	wallNow := a.clock.Now()

	out := []ports.Entry{}
	var k [allowKeySize]byte
	var v uint64

	it := a.m.Iterate()
	for it.Next(unsafe.Pointer(&k[0]), unsafe.Pointer(&v)) {
		e := ports.Entry{IP: addrFromKey(k), Port: binary.NativeEndian.Uint16(k[16:18])}
		switch {
		case v == expiredForever:
			e.Forever = true
		case v > now:
			// 剩余单调时间换算成墙钟：List 的输出要给人和 CLI 看。
			e.ExpiresAt = wallNow.Add(time.Duration(v - now))
		default:
			continue // 已过期：与数据面的判断一致，不展示
		}
		out = append(out, e)
	}
	if err := it.Err(); err != nil {
		return out, err
	}
	return out, nil
}

//go:build linux

// allowKey / addrFromKey 的纯函数单测：map key 的字节布局是 C/Go 共享的 ABI，
// 编码错一个字节的后果是"授权永远匹配不上"（静默失效），所以这里逐字节钉住。
// 不需要 root，服务器上 `go test ./...` 即可跑；内核侧的证明在
// dataplane_integration_test.go（授权后 stats 的 allow_hit 真的递增）。

package ebpfplat

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestAllowKeyIPv4IsV4Mapped(t *testing.T) {
	k := allowKey(netip.MustParseAddr("10.1.2.3"), 4242)

	// 前 10 字节必须全零，10..11 = 0xffff，12..15 = 地址：
	// C 侧是 key.ip[10]=key.ip[11]=0xff; memcpy(&key.ip[12], &iph->saddr, 4)。
	for i := 0; i < 10; i++ {
		if k[i] != 0 {
			t.Fatalf("k[%d] = %#x, want 0（v4-mapped 前缀）", i, k[i])
		}
	}
	if k[10] != 0xff || k[11] != 0xff {
		t.Fatalf("k[10:12] = %#x %#x, want ff ff", k[10], k[11])
	}
	if got := [4]byte{k[12], k[13], k[14], k[15]}; got != [4]byte{10, 1, 2, 3} {
		t.Fatalf("k[12:16] = %v, want [10 1 2 3]", got)
	}
	if k[18] != 0 || k[19] != 0 {
		t.Fatalf("pad = %v, want 0", k[18:20])
	}
	if got := binary.NativeEndian.Uint16(k[16:18]); got != 4242 {
		t.Fatalf("port = %d, want 4242（主机序）", got)
	}
}

func TestAllowKeyIPv4AndV4In6Agree(t *testing.T) {
	// C 侧只有一种 IPv4 形态，所以 4 字节与 ::ffff: 两种写法必须编码成同一个 key
	// （否则"客户端来包是 v4-mapped、Grant 用 4 字节"就会静默不匹配）。
	a := allowKey(netip.MustParseAddr("10.1.2.3"), 4242)
	b := allowKey(netip.MustParseAddr("::ffff:10.1.2.3"), 4242)
	if a != b {
		t.Fatalf("10.1.2.3 与 ::ffff:10.1.2.3 的 key 不同:\n %v\n %v", a, b)
	}
}

func TestAllowKeyIPv6(t *testing.T) {
	ip := netip.MustParseAddr("2001:db8::1")
	k := allowKey(ip, 65535)

	if want := ip.As16(); [16]byte(k[0:16]) != want {
		t.Fatalf("k[0:16] = %v, want %v", k[0:16], want)
	}
	if got := binary.NativeEndian.Uint16(k[16:18]); got != 65535 {
		t.Fatalf("port = %d, want 65535", got)
	}
}

func TestAddrFromKeyRoundTrip(t *testing.T) {
	// 第 6 组正好是 ffff 的**真实 IPv6** 地址不能按 v4-mapped 解码（否则会变成
	// 0.1.0.2）；v4-mapped 则解码回 4 字节形式（与 Grant 时的常见写法一致）。
	for _, tc := range []struct{ in, want string }{
		{"10.1.2.3", "10.1.2.3"},
		{"::ffff:10.1.2.3", "10.1.2.3"},
		{"2001:db8::1", "2001:db8::1"},
		{"2001:db8::ffff:1:2", "2001:db8::ffff:1:2"},
		{"::1", "::1"},
	} {
		k := allowKey(netip.MustParseAddr(tc.in), 7)
		if got := addrFromKey(k); got != netip.MustParseAddr(tc.want) {
			t.Errorf("addrFromKey(allowKey(%s)) = %v, want %v", tc.in, got, tc.want)
		}
		if binary.NativeEndian.Uint16(k[16:18]) != 7 {
			t.Errorf("%s: 端口在编码里丢失", tc.in)
		}
	}
}

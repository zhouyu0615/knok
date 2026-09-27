//go:build linux

// parseEvent 的纯函数单测：ringbuf 样本的字节布局是 C/Go 两侧共享的 ABI，
// 而集成测试只能覆盖 IPv4 + 正常长度这一条路径（lo 上跑不出 IPv6，也造不出
// 错位样本）。这里用合成样本把其余分支与越界防护钉住——不需要 root，服务器上
// `go test ./...` 即可跑。

package ebpfplat

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

// makeEvent 按 struct spa_event 的布局造一个样本（EvOff* 常量即布局本身，
// 所以这个函数不会和 C 侧再各写一份魔数）。
func makeEvent(ipver byte, src [16]byte, dstPort uint16, payload []byte) []byte {
	d := make([]byte, EvSize)
	binary.LittleEndian.PutUint64(d[EvOffTS:], 12345)
	binary.LittleEndian.PutUint32(d[EvOffIfindex:], 7)
	d[EvOffIPVer] = ipver
	copy(d[EvOffSrcIP:EvOffSrcIP+16], src[:])
	binary.LittleEndian.PutUint16(d[EvOffSrcPort:], 40000)
	binary.LittleEndian.PutUint16(d[EvOffDstPort:], dstPort)
	binary.LittleEndian.PutUint16(d[EvOffPLen:], uint16(len(payload)))
	copy(d[EvOffPayload:], payload)
	return d
}

func TestParseEventIPv4UsesV4MappedSlot(t *testing.T) {
	// C 侧 IPv4 也写 16 字节：前 12 字节是 ::ffff 前缀，4 字节地址在 [12:16]。
	var src [16]byte
	src[10], src[11] = 0xff, 0xff
	copy(src[12:16], []byte{127, 0, 0, 1})

	pkt, ok := parseEvent(makeEvent(4, src, 4242, []byte("KNOKpayload")))
	if !ok {
		t.Fatal("合法样本被拒绝")
	}
	if pkt.SrcIP != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("SrcIP = %v, want 127.0.0.1", pkt.SrcIP)
	}
	if pkt.DstPort != 4242 {
		t.Fatalf("DstPort = %d, want 4242", pkt.DstPort)
	}
	if pkt.IfIndex != 7 {
		t.Fatalf("IfIndex = %d, want 7", pkt.IfIndex)
	}
	if string(pkt.Payload) != "KNOKpayload" {
		t.Fatalf("Payload = %q, want %q", pkt.Payload, "KNOKpayload")
	}
	if pkt.ReceivedAt.IsZero() {
		t.Fatal("ReceivedAt 为零值")
	}
}

func TestParseEventIPv6(t *testing.T) {
	// ipver != 4 时整 16 字节就是地址本身（不剥 v4-mapped 前缀）。
	src := netip.MustParseAddr("2001:db8::1").As16()

	pkt, ok := parseEvent(makeEvent(6, src, 4242, []byte("KNOK")))
	if !ok {
		t.Fatal("合法 IPv6 样本被拒绝")
	}
	if pkt.SrcIP != netip.MustParseAddr("2001:db8::1") {
		t.Fatalf("SrcIP = %v, want 2001:db8::1", pkt.SrcIP)
	}
	if len(pkt.Payload) != 4 {
		t.Fatalf("Payload 长度 = %d, want 4", len(pkt.Payload))
	}
}

func TestParseEventRejectsMalformed(t *testing.T) {
	full := makeEvent(4, [16]byte{10: 0xff, 11: 0xff, 15: 1}, 4242, []byte("KNOK"))

	// plen 越界：0、> MaxSPAPkt，以及"声称的长度比样本还长"（越界读取防护）。
	zeroLen := makeEvent(4, [16]byte{}, 4242, nil) // plen = 0
	tooLong := makeEvent(4, [16]byte{}, 4242, []byte("KNOK"))
	binary.LittleEndian.PutUint16(tooLong[EvOffPLen:], MaxSPAPkt+1)
	truncated := makeEvent(4, [16]byte{}, 4242, []byte("KNOK"))
	binary.LittleEndian.PutUint16(truncated[EvOffPLen:], 500) // 声称 500 字节
	truncated = truncated[:EvOffPayload+4]                    // …样本里只有 4 字节

	for _, tc := range []struct {
		name string
		d    []byte
	}{
		{"空样本", nil},
		{"头部不完整", full[:EvOffPayload-1]},
		{"plen 为 0", zeroLen},
		{"plen 超过 MaxSPAPkt", tooLong},
		{"样本比 plen 短", truncated},
	} {
		if _, ok := parseEvent(tc.d); ok {
			t.Errorf("%s: 被接受了（应丢弃）", tc.name)
		}
	}

	// 边界对照：恰好 plen = MaxSPAPkt 的完整样本必须被接受。
	max := makeEvent(4, [16]byte{}, 4242, make([]byte, MaxSPAPkt))
	if _, ok := parseEvent(max); !ok {
		t.Error("plen = MaxSPAPkt 的完整样本被拒绝（上界判断过严）")
	}
}

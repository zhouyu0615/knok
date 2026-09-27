package ebpfplat

import (
	"fmt"
	"testing"

	"github.com/zhouyu0615/knok/internal/platform/mark"
)

// spa_event 的字节偏移是 BPF C 侧 struct spa_event 与 Go 侧共享的 ABI：
// 这些字面量必须与 bpf/knok_ingress.c 的字段顺序、宽度、对齐完全一致。
// 任一侧单独改动而另一侧未改，ringbuf 事件就会被解析成垃圾或越界读取。
func TestSPAEventLayout(t *testing.T) {
	for _, tc := range []struct {
		name string
		got  int
		want int
	}{
		{"EvOffTS", EvOffTS, 0},           // u64 ts_ns
		{"EvOffIfindex", EvOffIfindex, 8}, // u32 ifindex
		{"EvOffIPVer", EvOffIPVer, 12},    // u8 ipver（+ u8 pad[3]）
		{"EvOffSrcIP", EvOffSrcIP, 16},    // u8 src_ip[16]
		{"EvOffSrcPort", EvOffSrcPort, 32},
		{"EvOffDstPort", EvOffDstPort, 34},
		{"EvOffPLen", EvOffPLen, 36},
		{"EvOffPayload", EvOffPayload, 38},
		{"EvSize", EvSize, 552},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %d, want %d (layout must match struct spa_event in bpf/knok_ingress.c)",
				tc.name, tc.got, tc.want)
		}
	}
}

// 事件长度由布局推导，而不是另写一个魔数：尾部补齐到 8 字节（u64 对齐），
// 也让 ringbuf 保留区的大小是常量、payload 的越界写入检查有确定上界。
func TestSPAEventSizeDerivedFromPayload(t *testing.T) {
	if EvSize != EvOffPayload+MaxSPAPkt+2 {
		t.Fatalf("EvSize = %d, want EvOffPayload(%d)+MaxSPAPkt(%d)+2 = %d",
			EvSize, EvOffPayload, MaxSPAPkt, EvOffPayload+MaxSPAPkt+2)
	}
	if EvSize%8 != 0 {
		t.Errorf("EvSize = %d, want 8-byte aligned", EvSize)
	}
}

// 字段偏移必须严格递增：重叠意味着 C 侧结构体被改坏，或这里的常量被改错。
func TestSPAEventOffsetsAscend(t *testing.T) {
	offs := []struct {
		name string
		off  int
	}{
		{"EvOffTS", EvOffTS},
		{"EvOffIfindex", EvOffIfindex},
		{"EvOffIPVer", EvOffIPVer},
		{"EvOffSrcIP", EvOffSrcIP},
		{"EvOffSrcPort", EvOffSrcPort},
		{"EvOffDstPort", EvOffDstPort},
		{"EvOffPLen", EvOffPLen},
		{"EvOffPayload", EvOffPayload},
	}
	for i := 1; i < len(offs); i++ {
		if offs[i].off <= offs[i-1].off {
			t.Fatalf("%s (%d) must follow %s (%d)", offs[i].name, offs[i].off, offs[i-1].name, offs[i-1].off)
		}
	}
	if EvOffPayload+MaxSPAPkt > EvSize {
		t.Fatalf("payload ends at %d, beyond EvSize = %d", EvOffPayload+MaxSPAPkt, EvSize)
	}
}

// stats 槽位与 C 侧 #define 一一对应；顺序即 ringbuf/映射读取的索引。
func TestStatsSlots(t *testing.T) {
	for _, tc := range []struct {
		name string
		got  int
		want int
	}{
		{"StTotal", StTotal, 0},
		{"StAllowHit", StAllowHit, 1},
		{"StAllowExpiry", StAllowExpiry, 2},
		{"StCandidate", StCandidate, 3},
		{"StRateDrop", StRateDrop, 4},
		{"StRingbufDrop", StRingbufDrop, 5},
		{"StSlots", StSlots, 6},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %d, want %d (must match the ST_* defines in bpf/knok_ingress.c)",
				tc.name, tc.got, tc.want)
		}
	}
}

// mark 是跨层唯一来源（Ruling 22）：eBPF 侧不得自带一份字面量。
func TestMarkKNOKComesFromSharedPackage(t *testing.T) {
	if MarkKNOK != mark.Mark {
		t.Fatalf("MarkKNOK = %#08x, want mark.Mark = %#08x", MarkKNOK, mark.Mark)
	}
	if uint32(MarkKNOK) != 0x4B4E4F4B {
		t.Fatalf("MarkKNOK = %#08x, want 0x4b4e4f4b", uint32(MarkKNOK))
	}
	if fmt.Sprintf("0x%08x", MarkKNOK) != mark.Hex {
		t.Fatalf("mark.Hex = %q disagrees with MarkKNOK = %#08x", mark.Hex, MarkKNOK)
	}
}

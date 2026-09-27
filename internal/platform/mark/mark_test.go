package mark

import (
	"fmt"
	"testing"
)

// Mark 与 Hex 必须描述同一个值：Hex 是 Mark 的渲染形式。一旦两者分叉，
// eBPF 写在 skb->mark 上的值与 nftables 匹配的值就不是同一个数，已授权
// 流量会被 nftables 的 drop 规则静默丢弃（Ruling 22 的存在理由）。
func TestMarkAndHexAgree(t *testing.T) {
	if got := fmt.Sprintf("0x%08x", Mark); got != Hex {
		t.Fatalf("Hex = %q, want %q (Mark = %#08x)", Hex, got, Mark)
	}
}

// 具体数值被冻结：spec §5.3 规定 SKB mark 为 0x4B4E4F4B，即大端顺序的
// ASCII "KNOK"；nft 规则文本只接受十六进制字面量，故 Hex 用小写形式。
func TestMarkIsKNOK(t *testing.T) {
	if Mark != 0x4B4E4F4B {
		t.Fatalf("Mark = %#08x, want 0x4b4e4f4b", Mark)
	}
	if Hex != "0x4b4e4f4b" {
		t.Fatalf("Hex = %q, want %q", Hex, "0x4b4e4f4b")
	}
	m := uint32(Mark) // 变量化后按字节截断（常量表达式会因溢出而编译失败）
	ascii := []byte{byte(m >> 24), byte(m >> 16), byte(m >> 8), byte(m)}
	if string(ascii) != "KNOK" {
		t.Fatalf("Mark spells %q, want %q", ascii, "KNOK")
	}
}

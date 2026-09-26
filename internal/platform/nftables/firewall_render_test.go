package nftables_test

import (
	"strings"
	"testing"

	"github.com/zhouyu0615/knok/internal/core/ports"
	knoknft "github.com/zhouyu0615/knok/internal/platform/nftables"
)

// Firewall 必须实现 core 的 ports.Firewall 端口（Task 9 按该接口消费）。
var _ ports.Firewall = knoknft.New()

func TestRenderRuleset(t *testing.T) {
	got := knoknft.RenderRuleset([]uint16{22, 2222}, 4242)
	for _, want := range []string{
		"table inet knok",
		"flush table inet knok",
		"type filter hook input priority -200",
		"meta mark 0x4b4e4f4b accept",
		"tcp dport { 22, 2222 } drop",
		"udp dport 4242 drop",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("ruleset missing %q:\n%s", want, got)
		}
	}
}

func TestRenderRulesetSortsAndDeduplicates(t *testing.T) {
	got := knoknft.RenderRuleset([]uint16{2222, 22, 2222, 22}, 4242)
	if !strings.Contains(got, "tcp dport { 22, 2222 } drop") {
		t.Errorf("protected ports not sorted/deduplicated:\n%s", got)
	}
}

func TestRenderRulesetNoProtectedPorts(t *testing.T) {
	got := knoknft.RenderRuleset(nil, 4242)
	if strings.Contains(got, "tcp dport") {
		t.Errorf("empty protected set must not render a tcp rule:\n%s", got)
	}
	if !strings.Contains(got, "udp dport 4242 drop") {
		t.Errorf("SPA port must stay dropped:\n%s", got)
	}
}

// mark accept 必须排在 drop 规则之前：accept 非终局（继续走用户链），
// drop 是终局——顺序颠倒会让已授权流量被自己的表丢掉。
func TestRenderRulesetMarkAcceptPrecedesDrops(t *testing.T) {
	if knoknft.MarkHex != "0x4b4e4f4b" {
		t.Fatalf("MarkHex = %q, must match the eBPF dataplane mark", knoknft.MarkHex)
	}
	got := knoknft.RenderRuleset([]uint16{22}, 4242)
	accept := strings.Index(got, "meta mark 0x4b4e4f4b accept")
	tcpDrop := strings.Index(got, "tcp dport { 22 } drop")
	udpDrop := strings.Index(got, "udp dport 4242 drop")
	if accept < 0 || tcpDrop < 0 || udpDrop < 0 || accept > tcpDrop || tcpDrop > udpDrop {
		t.Errorf("rule order accept < tcp drop < udp drop violated (accept=%d tcp=%d udp=%d):\n%s",
			accept, tcpDrop, udpDrop, got)
	}
}

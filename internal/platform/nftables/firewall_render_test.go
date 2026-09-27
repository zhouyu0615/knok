package nftables_test

import (
	"strings"
	"testing"

	"github.com/zhouyu0615/knok/internal/core/ports"
	"github.com/zhouyu0615/knok/internal/platform/mark"
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
		"udp dport { 22, 2222 } drop",
		"udp dport 4242 drop",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("ruleset missing %q:\n%s", want, got)
		}
	}
}

// 受保护端口的裁决必须**同时**覆盖 tcp 与 udp：spec 的"无 mark 即 drop"契约不区分
// 协议，而 eBPF 数据面对两种协议都打 mark（M2 起 TCP 也打）——只渲染 tcp 规则会让
// 一个"受保护"的 UDP 端口对所有人大开，而命令看起来成功。
func TestRenderRulesetDropsBothProtocolsForEveryProtectedPort(t *testing.T) {
	got := knoknft.RenderRuleset([]uint16{2222}, 4242)
	for _, want := range []string{"tcp dport { 2222 } drop", "udp dport { 2222 } drop"} {
		if !strings.Contains(got, want) {
			t.Errorf("protected port 2222 not dropped for both protocols, missing %q:\n%s", want, got)
		}
	}
}

func TestRenderRulesetSortsAndDeduplicates(t *testing.T) {
	got := knoknft.RenderRuleset([]uint16{2222, 22, 2222, 22}, 4242)
	for _, want := range []string{"tcp dport { 22, 2222 } drop", "udp dport { 22, 2222 } drop"} {
		if !strings.Contains(got, want) {
			t.Errorf("protected ports not sorted/deduplicated, missing %q:\n%s", want, got)
		}
	}
}

func TestRenderRulesetNoProtectedPorts(t *testing.T) {
	got := knoknft.RenderRuleset(nil, 4242)
	// "dport {" 只在受保护端口的多值集合里出现；SPA 端口是单值规则。
	if strings.Contains(got, "dport {") {
		t.Errorf("empty protected set must not render a protected-port rule:\n%s", got)
	}
	if !strings.Contains(got, "udp dport 4242 drop") {
		t.Errorf("SPA port must stay dropped:\n%s", got)
	}
}

// mark accept 必须排在 drop 规则之前：accept 非终局（继续走用户链），
// drop 是终局——顺序颠倒会让已授权流量被自己的表丢掉。
func TestRenderRulesetMarkAcceptPrecedesDrops(t *testing.T) {
	// mark 值本身仍是独立钉住的字面量：共享常量（internal/platform/mark）
	// 被改动时这里必须一起改，而不是跟着漂移。
	if mark.Hex != "0x4b4e4f4b" {
		t.Fatalf("mark.Hex = %q, must match the eBPF dataplane mark", mark.Hex)
	}
	got := knoknft.RenderRuleset([]uint16{22}, 4242)
	accept := strings.Index(got, "meta mark 0x4b4e4f4b accept")
	tcpDrop := strings.Index(got, "tcp dport { 22 } drop")
	udpDrop := strings.Index(got, "udp dport { 22 } drop")
	spaDrop := strings.Index(got, "udp dport 4242 drop")
	if accept < 0 || tcpDrop < 0 || udpDrop < 0 || spaDrop < 0 ||
		accept > tcpDrop || tcpDrop > udpDrop || udpDrop > spaDrop {
		t.Errorf("rule order accept < tcp drop < udp drop < spa drop violated (accept=%d tcp=%d udp=%d spa=%d):\n%s",
			accept, tcpDrop, udpDrop, spaDrop, got)
	}
}

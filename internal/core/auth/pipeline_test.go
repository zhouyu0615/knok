package auth_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/zhouyu0615/knok/internal/core/auth"
	"github.com/zhouyu0615/knok/internal/core/ports"
	"github.com/zhouyu0615/knok/internal/core/testfakes"
	"github.com/zhouyu0615/knok/pkg/protocol"
)

var psk = [32]byte{42}
var baseTime = time.Unix(1758900000, 0)

func newPipeline(t *testing.T, clock *testfakes.FakeClock) *auth.Pipeline {
	t.Helper()
	return auth.NewPipeline(auth.Config{
		PSK: psk, AllowedPorts: []uint16{22}, MaxTTL: 30 * time.Minute,
		TSWindow: 300 * time.Second,
	}, clock)
}

// candidate 把裸 payload 包装成管线输入（dstPort 是 eBPF 命中的 SPA UDP 端口，
// 与内层请求的端口无关——内层端口来自 Message.Ports）。
func candidate(raw []byte, dstPort uint16) ports.CandidatePacket {
	return ports.CandidatePacket{
		SrcIP: netip.MustParseAddr("203.0.113.9"), DstPort: dstPort,
		Payload: raw, ReceivedAt: baseTime,
	}
}

func validMsg(nonce byte) protocol.Message {
	var n [16]byte
	n[0] = nonce
	return protocol.Message{TS: uint64(baseTime.Unix()), Nonce: n, Ports: []uint16{22}, TTL: 60}
}

func TestPipelineAllow(t *testing.T) {
	clock := testfakes.NewFakeClock(baseTime)
	p := newPipeline(t, clock)
	raw, _ := protocol.EncodePSK(validMsg(1), psk)
	d := p.Evaluate(candidate(raw, 22))
	if !d.Allowed || d.TTL != 60*time.Second {
		t.Fatalf("expected allow with 60s ttl, got %+v", d)
	}
}

func TestPipelineRejects(t *testing.T) {
	clock := testfakes.NewFakeClock(baseTime)
	p := newPipeline(t, clock)

	// 垃圾包
	if d := p.Evaluate(candidate([]byte("junk junk junk"), 22)); d.Allowed || d.RejectReason != "bad_packet" {
		t.Fatalf("junk: %+v", d)
	}
	// 错误密钥
	bad, _ := protocol.EncodePSK(validMsg(2), [32]byte{99})
	if d := p.Evaluate(candidate(bad, 22)); d.Allowed || d.RejectReason != "auth_failed" {
		t.Fatalf("wrong key: %+v", d)
	}
	// 时钟偏移（ts 超前 1 小时）
	m := validMsg(3)
	m.TS = uint64(baseTime.Add(time.Hour).Unix())
	skew, _ := protocol.EncodePSK(m, psk)
	if d := p.Evaluate(candidate(skew, 22)); d.Allowed || d.RejectReason != "clock_skew" {
		t.Fatalf("skew: %+v", d)
	}
	// 重放：同一包发两次
	replayRaw, _ := protocol.EncodePSK(validMsg(4), psk)
	if d := p.Evaluate(candidate(replayRaw, 22)); !d.Allowed {
		t.Fatalf("first use should pass: %+v", d)
	}
	if d := p.Evaluate(candidate(replayRaw, 22)); d.Allowed || d.RejectReason != "replay" {
		t.Fatalf("replay: %+v", d)
	}
	// 策略越权：请求 23 端口（仅 22 允许）
	m2 := validMsg(5)
	m2.Ports = []uint16{23}
	pol, _ := protocol.EncodePSK(m2, psk)
	if d := p.Evaluate(candidate(pol, 22)); d.Allowed || d.RejectReason != "policy" {
		t.Fatalf("policy: %+v", d)
	}
}

func TestPipelineTTLCap(t *testing.T) {
	clock := testfakes.NewFakeClock(baseTime)
	p := newPipeline(t, clock)
	m := validMsg(6)
	m.TTL = 999999 // 远超 MaxTTL=30m
	raw, _ := protocol.EncodePSK(m, psk)
	d := p.Evaluate(candidate(raw, 22))
	if !d.Allowed || d.TTL != 30*time.Minute {
		t.Fatalf("ttl should cap at 30m, got %+v", d)
	}
}

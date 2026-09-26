package auth_test

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/zhouyu0615/knok/internal/core/auth"
	"github.com/zhouyu0615/knok/internal/core/ports"
	"github.com/zhouyu0615/knok/internal/core/testfakes"
	"github.com/zhouyu0615/knok/pkg/protocol"
)

func TestAuthenticatorGrantsAllowlist(t *testing.T) {
	clock := testfakes.NewFakeClock(baseTime)
	src := testfakes.NewChanSource(4)
	al := testfakes.NewMemAllowlist(clock)
	pipe := auth.NewPipeline(auth.Config{PSK: psk, AllowedPorts: []uint16{22},
		MaxTTL: 30 * time.Minute, TSWindow: 300 * time.Second}, clock)
	a := auth.NewAuthenticator(src, pipe, al, auth.LogAuditSink{Logger: slog.Default()})

	raw, _ := protocol.EncodePSK(validMsg(7), psk)
	src.Send(ports.CandidatePacket{SrcIP: netip.MustParseAddr("203.0.113.9"),
		DstPort: 4242, Payload: raw, ReceivedAt: baseTime})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()

	deadline := time.Now().Add(2 * time.Second)
	for !al.Has(netip.MustParseAddr("203.0.113.9"), 22) {
		if time.Now().After(deadline) {
			t.Fatal("grant not observed within 2s")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	src.Close()
	<-done
}

// TestAuthenticatorGrantsEveryPortAndAuditsOnce 验证：一包请求多个端口时全部授权，
// 且每个包恰好产生一条 audit 事件；TTL 以 MaxTTL 封顶后写入 allowlist。
func TestAuthenticatorGrantsEveryPortAndAuditsOnce(t *testing.T) {
	clock := testfakes.NewFakeClock(baseTime)
	src := testfakes.NewChanSource(4)
	al := testfakes.NewMemAllowlist(clock)
	sink := &recorder{}
	pipe := auth.NewPipeline(auth.Config{PSK: psk, AllowedPorts: []uint16{22, 8080},
		MaxTTL: 30 * time.Minute, TSWindow: 300 * time.Second}, clock)
	a := auth.NewAuthenticator(src, pipe, al, sink)

	m := validMsg(9)
	m.Ports = []uint16{8080, 22}
	m.TTL = 999999 // 必须被 MaxTTL=30m 封顶
	raw, err := protocol.EncodePSK(m, psk)
	if err != nil {
		t.Fatal(err)
	}
	src.Send(candidate(raw, 4242))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()

	ev := sink.waitFor(t, 1)
	if !ev[0].d.Allowed || len(ev[0].d.Ports) != 2 {
		t.Fatalf("expected allow for 2 ports, got %+v", ev[0].d)
	}
	ip := netip.MustParseAddr("203.0.113.9")
	if !al.Has(ip, 22) || !al.Has(ip, 8080) {
		t.Fatal("expected both requested ports granted")
	}
	// TTL 封顶必须在回写 allowlist 时生效：29 分钟仍存活，31 分钟后过期。
	clock.Advance(29 * time.Minute)
	if !al.Has(ip, 22) || !al.Has(ip, 8080) {
		t.Fatal("grant expired before the 30m cap")
	}
	clock.Advance(2 * time.Minute)
	if al.Has(ip, 22) || al.Has(ip, 8080) {
		t.Fatal("grant outlived the 30m cap (ttl not capped)")
	}

	cancel()
	src.Close()
	<-done

	if n := len(sink.snapshot()); n != 1 {
		t.Fatalf("expected exactly 1 audit event, got %d", n)
	}
}

// TestAuthenticatorGrantFailureAuditedAsReject 验证：数据面写授权失败时决策必须
// 变为拒绝且 RejectReason == "grant_failed"，不允许静默放行。
func TestAuthenticatorGrantFailureAuditedAsReject(t *testing.T) {
	clock := testfakes.NewFakeClock(baseTime)
	src := testfakes.NewChanSource(4)
	sink := &recorder{}
	pipe := newPipeline(t, clock)
	a := auth.NewAuthenticator(src, pipe, failAllowlist{err: errors.New("map update failed")}, sink)

	raw, err := protocol.EncodePSK(validMsg(10), psk)
	if err != nil {
		t.Fatal(err)
	}
	src.Send(candidate(raw, 4242))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()

	ev := sink.waitFor(t, 1)
	if ev[0].d.Allowed || ev[0].d.RejectReason != "grant_failed" {
		t.Fatalf("expected grant_failed reject, got %+v", ev[0].d)
	}

	defer cancel()
	if err := src.Close(); err != nil {
		t.Fatal(err)
	}
	<-done
}

// TestAuthenticatorRejectGrantsNothing 验证：验证失败的包不产生任何 allowlist 条目，
// 并且仍然产生恰好一条 audit 事件（拒绝也必须可审计）。
func TestAuthenticatorRejectGrantsNothing(t *testing.T) {
	clock := testfakes.NewFakeClock(baseTime)
	src := testfakes.NewChanSource(4)
	al := testfakes.NewMemAllowlist(clock)
	sink := &recorder{}
	a := auth.NewAuthenticator(src, newPipeline(t, clock), al, sink)

	src.Send(candidate([]byte("junk junk junk"), 4242))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()

	ev := sink.waitFor(t, 1)
	if ev[0].d.Allowed || ev[0].d.RejectReason != "bad_packet" {
		t.Fatalf("expected bad_packet reject, got %+v", ev[0].d)
	}
	entries, err := al.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("rejected packet must not grant anything, got %+v", entries)
	}

	// ctx 未取消时关闭 source：Run 必须正常返回 nil（不是 ctx.Err()）。
	if err := src.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("Run should return nil on source close, got %v", err)
	}
	cancel()

	if n := len(sink.snapshot()); n != 1 {
		t.Fatalf("expected exactly 1 audit event, got %d", n)
	}
}

// failAllowlist 模拟数据面授权写入失败。
type failAllowlist struct{ err error }

func (f failAllowlist) Grant(netip.Addr, uint16, time.Duration) error { return f.err }
func (f failAllowlist) GrantForever(netip.Addr, uint16) error         { return f.err }
func (f failAllowlist) Revoke(netip.Addr, uint16) error               { return f.err }
func (f failAllowlist) List() ([]ports.Entry, error)                  { return nil, f.err }

// recorder 是内存 AuditSink，用于断言事件内容与“每包恰好一条”。
type recorder struct {
	mu  sync.Mutex
	got []recorded
}

type recorded struct {
	d   ports.Decision
	pkt ports.CandidatePacket
}

func (r *recorder) Emit(d ports.Decision, pkt ports.CandidatePacket) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.got = append(r.got, recorded{d: d, pkt: pkt})
}

func (r *recorder) snapshot() []recorded {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]recorded(nil), r.got...)
}

func (r *recorder) waitFor(t *testing.T, n int) []recorded {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		got := r.snapshot()
		if len(got) >= n {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("expected %d audit event(s) within 2s, got %d", n, len(got))
		}
		time.Sleep(5 * time.Millisecond)
	}
}

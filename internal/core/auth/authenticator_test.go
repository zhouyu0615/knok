package auth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/netip"
	"slices"
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

// TestAuthenticatorReportsPartialGrantTruthfully 验证：多端口请求中某个端口 Grant 失败时，
// 决策必须真实反映"部分授权"——停止后续端口、Ports 收敛为本次实际授权的子集、审计仍恰好一条
// 且携带该子集。不回滚已成功端口（可能来自同一客户端早先的包）。
func TestAuthenticatorReportsPartialGrantTruthfully(t *testing.T) {
	clock := testfakes.NewFakeClock(baseTime)
	src := testfakes.NewChanSource(4)
	sink := &recorder{}
	al := &countingAllowlist{failPort: 23, err: errors.New("map update failed")}
	pipe := auth.NewPipeline(auth.Config{PSK: psk, AllowedPorts: []uint16{22, 23, 24},
		MaxTTL: 30 * time.Minute, TSWindow: 300 * time.Second}, clock)
	a := auth.NewAuthenticator(src, pipe, al, sink)

	m := validMsg(11)
	m.Ports = []uint16{22, 23, 24}
	raw, err := protocol.EncodePSK(m, psk)
	if err != nil {
		t.Fatal(err)
	}
	src.Send(candidate(raw, 4242))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()

	ev := sink.waitFor(t, 1)

	// 1) 失败端口之后的端口不再尝试授权；失败端口本身被尝试过。
	if got := al.attempts(); !slices.Equal(got, []uint16{22, 23}) {
		t.Fatalf("expected attempts [22 23] (stop at first failure), got %v", got)
	}
	// 2) 决策真实：拒绝 + grant_failed + 仅含实际授权的子集。
	if ev[0].d.Allowed || ev[0].d.RejectReason != "grant_failed" {
		t.Fatalf("expected grant_failed reject, got %+v", ev[0].d)
	}
	if !slices.Equal(ev[0].d.Ports, []uint16{22}) {
		t.Fatalf("expected decision ports to be the granted subset [22], got %v", ev[0].d.Ports)
	}
	if got := al.grantedPorts(); !slices.Equal(got, []uint16{22}) {
		t.Fatalf("expected only port 22 granted, got %v", got)
	}
	if got := al.revoked(); len(got) != 0 {
		t.Fatalf("granted ports must not be rolled back, got revokes %v", got)
	}

	cancel()
	src.Close()
	<-done

	// 3) 恰好一条 audit 事件，且它携带实际授权的子集。
	if n := len(sink.snapshot()); n != 1 {
		t.Fatalf("expected exactly 1 audit event, got %d", n)
	}
}

// TestAuthenticatorFirstPortGrantFailureReportsEmptySubset 验证：首个端口就失败时，
// Ports 是空切片（非 nil 语义歧义）——拒绝且没有端口被打开。
func TestAuthenticatorFirstPortGrantFailureReportsEmptySubset(t *testing.T) {
	clock := testfakes.NewFakeClock(baseTime)
	src := testfakes.NewChanSource(4)
	sink := &recorder{}
	al := &countingAllowlist{failPort: 22, err: errors.New("map update failed")}
	pipe := auth.NewPipeline(auth.Config{PSK: psk, AllowedPorts: []uint16{22, 23},
		MaxTTL: 30 * time.Minute, TSWindow: 300 * time.Second}, clock)
	a := auth.NewAuthenticator(src, pipe, al, sink)

	m := validMsg(12)
	m.Ports = []uint16{22, 23}
	raw, err := protocol.EncodePSK(m, psk)
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
	if ev[0].d.Ports == nil || len(ev[0].d.Ports) != 0 {
		t.Fatalf("expected non-nil empty granted subset, got %#v", ev[0].d.Ports)
	}
	if got := al.attempts(); !slices.Equal(got, []uint16{22}) {
		t.Fatalf("expected attempts [22] only, got %v", got)
	}

	cancel()
	src.Close()
	<-done
}

// TestLogAuditSinkPartialGrantVisibility 验证：grant_failed 的 spa_reject 行携带
// granted_ports 属性（部分授权对运维可见）；无授权子集的普通拒绝不带该属性。
func TestLogAuditSinkPartialGrantVisibility(t *testing.T) {
	var buf bytes.Buffer
	sink := auth.LogAuditSink{Logger: slog.New(slog.NewJSONHandler(&buf, nil))}
	pkt := candidate([]byte("x"), 4242)

	sink.Emit(ports.Decision{RejectReason: "grant_failed", Ports: []uint16{22}}, pkt)
	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("expected JSON log line, got %q: %v", buf.String(), err)
	}
	if rec["msg"] != "spa_reject" || rec["reason"] != "grant_failed" {
		t.Fatalf("expected spa_reject/grant_failed, got %v", rec)
	}
	got, ok := rec["granted_ports"].([]any)
	if !ok || len(got) != 1 || got[0].(float64) != 22 {
		t.Fatalf("expected granted_ports [22] on the reject line, got %v", rec["granted_ports"])
	}

	buf.Reset()
	sink.Emit(ports.Decision{RejectReason: "bad_packet"}, pkt)
	rec = map[string]any{}
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatal(err)
	}
	if _, present := rec["granted_ports"]; present {
		t.Fatalf("reject without granted subset must not carry granted_ports, got %v", rec)
	}
}

// countingAllowlist 记录 Grant 尝试与成功端口，并对指定端口返回错误。
type countingAllowlist struct {
	mu        sync.Mutex
	failPort  uint16
	err       error
	attempted []uint16
	granted   []uint16
	revokes   []uint16
}

func (c *countingAllowlist) Grant(_ netip.Addr, port uint16, _ time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.attempted = append(c.attempted, port)
	if port == c.failPort {
		return c.err
	}
	c.granted = append(c.granted, port)
	return nil
}

func (c *countingAllowlist) GrantForever(netip.Addr, uint16) error { return nil }

func (c *countingAllowlist) Revoke(_ netip.Addr, port uint16) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.revokes = append(c.revokes, port)
	return nil
}

func (c *countingAllowlist) List() ([]ports.Entry, error) { return nil, nil }

func (c *countingAllowlist) attempts() []uint16 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]uint16(nil), c.attempted...)
}

func (c *countingAllowlist) grantedPorts() []uint16 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]uint16(nil), c.granted...)
}

func (c *countingAllowlist) revoked() []uint16 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]uint16(nil), c.revokes...)
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

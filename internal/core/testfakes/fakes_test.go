package testfakes_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/zhouyu0615/knok/internal/core/testfakes"
)

func TestMemAllowlistExpiry(t *testing.T) {
	clock := testfakes.NewFakeClock(time.Unix(1000, 0))
	al := testfakes.NewMemAllowlist(clock)
	ip := netip.MustParseAddr("203.0.113.7")

	if err := al.Grant(ip, 22, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	if !al.Has(ip, 22) {
		t.Fatal("expected granted entry to be present")
	}
	clock.Advance(31 * time.Second)
	if al.Has(ip, 22) {
		t.Fatal("expected entry to expire after TTL")
	}
	entries, _ := al.List()
	if len(entries) != 0 {
		t.Fatalf("expected empty list after expiry, got %d", len(entries))
	}
}

// TestMemAllowlistExpiryBoundary 钉住过期边界的约定：一条授权严格存活到它的过期时刻之前，
// 当 now == ExpiresAt 时即视为已过期。此约定与 eBPF 数据面的判断
// （`*expiry > bpf_ktime_get_ns()`）以及 ports.Allowlist 的文档一致。
func TestMemAllowlistExpiryBoundary(t *testing.T) {
	clock := testfakes.NewFakeClock(time.Unix(1000, 0))
	al := testfakes.NewMemAllowlist(clock)
	ip := netip.MustParseAddr("192.0.2.9")
	const ttl = 30 * time.Second

	if err := al.Grant(ip, 22, ttl); err != nil {
		t.Fatal(err)
	}

	// 边界前 1ns：Has 与 List 都必须报告授权仍然存活。
	clock.Advance(ttl - time.Nanosecond)
	if !al.Has(ip, 22) {
		t.Fatal("expected Has to report entry live at TTL-1ns")
	}
	entries, err := al.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected List to report 1 entry live at TTL-1ns, got %d", len(entries))
	}

	// 恰好落在 ExpiresAt：Has 与 List 都必须报告该授权已过期。
	clock.Advance(time.Nanosecond)
	if al.Has(ip, 22) {
		t.Fatal("expected Has to report entry absent at exactly ExpiresAt")
	}
	entries, err = al.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected List to drop entry at exactly ExpiresAt, got %d entries", len(entries))
	}
}

func TestMemAllowlistForever(t *testing.T) {
	clock := testfakes.NewFakeClock(time.Unix(1000, 0))
	al := testfakes.NewMemAllowlist(clock)
	ip := netip.MustParseAddr("198.51.100.1")
	if err := al.GrantForever(ip, 22); err != nil {
		t.Fatal(err)
	}
	clock.Advance(100 * 365 * 24 * time.Hour)
	if !al.Has(ip, 22) {
		t.Fatal("forever entry must not expire")
	}
}

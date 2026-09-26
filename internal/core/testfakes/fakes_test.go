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

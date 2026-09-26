//go:build !linux

package nftables_test

import (
	"strings"
	"testing"

	knoknft "github.com/zhouyu0615/knok/internal/platform/nftables"
)

// 非 Linux 桩必须明确报错（而不是静默成功，静默成功会让调用方以为端口已被保护）。
func TestExecPathIsLinuxOnly(t *testing.T) {
	f := knoknft.New()
	if err := f.EnsureProtectedPorts([]uint16{22}, 4242); err == nil || !strings.Contains(err.Error(), "nftables: linux only") {
		t.Errorf("EnsureProtectedPorts err = %v, want %q", err, "nftables: linux only")
	}
	if err := f.Uninstall(); err == nil || !strings.Contains(err.Error(), "nftables: linux only") {
		t.Errorf("Uninstall err = %v, want %q", err, "nftables: linux only")
	}
}

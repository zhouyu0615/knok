//go:build linux && integration

package nftables_test

import (
	"os/exec"
	"strings"
	"testing"

	knoknft "github.com/zhouyu0615/knok/internal/platform/nftables"
)

// 需要真实 Linux 内核 + nft 二进制 + root：仅在 VPS 上运行
// （sudo -E go test -tags=integration ./internal/platform/nftables/ -v）。
func TestEnsureAndUninstall(t *testing.T) {
	f := knoknft.New()
	if err := f.EnsureProtectedPorts([]uint16{62222}, 64242); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("nft", "list", "table", "inet", "knok").CombinedOutput()
	if err != nil {
		t.Fatalf("table missing: %s", out)
	}
	if !strings.Contains(string(out), "62222") {
		t.Fatalf("protected port missing:\n%s", out)
	}
	// 幂等：重复应用
	if err := f.EnsureProtectedPorts([]uint16{62222}, 64242); err != nil {
		t.Fatal(err)
	}
	if err := f.Uninstall(); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("nft", "list", "table", "inet", "knok").CombinedOutput(); err == nil {
		t.Fatalf("table should be gone:\n%s", out)
	}
}

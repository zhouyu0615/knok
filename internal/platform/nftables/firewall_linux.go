//go:build linux

package nftables

import (
	"fmt"
	"os/exec"
	"strings"
)

// EnsureProtectedPorts 用 nft -f - 做整表声明式替换：受保护的 TCP 端口无 mark
// 即 drop（终局），SPA UDP 端口静默 drop。这是低频控制面操作（仅启动/配置变更
// 时执行一次），与 fwknop 每包 fork/exec 的性质不同。
//
// 只写 knok 独占的 inet knok 表，永不触碰用户自己的表。
func (f *Firewall) EnsureProtectedPorts(protected []uint16, spaPort uint16) error {
	return nftApply(RenderRuleset(protected, spaPort))
}

// Uninstall 拆除 inet knok 表（knokd --uninstall 路径）。
// `delete table` 在表不存在时会报错，故先 add 保证幂等：表不存在则先建后删，
// 表存在则 add 成功（nft 的 add 对已存在对象不报错）后删掉。
func (f *Firewall) Uninstall() error {
	return nftApply("add table inet knok\ndelete table inet knok\n")
}

// nftApply 把规则文本通过 stdin 交给系统 nft 二进制执行（nft -f -）。
func nftApply(ruleset string) error {
	if _, err := exec.LookPath("nft"); err != nil {
		return fmt.Errorf("nft binary not found: %w", err)
	}
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(ruleset)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft apply: %w: %s", err, out)
	}
	return nil
}

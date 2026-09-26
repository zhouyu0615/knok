//go:build !linux

package nftables

import "errors"

// errLinuxOnly 是非 Linux 构建里全部执行路径的返回值：nft 二进制与内核
// netfilter 都是 Linux 专属，macOS/Windows 上仅提供渲染能力（RenderRuleset）。
// 返回明确的错误而不是静默成功——静默成功会让调用方以为端口已被保护。
var errLinuxOnly = errors.New("nftables: linux only")

// EnsureProtectedPorts 在非 Linux 平台上不可用：与 firewall_linux.go 的实现
// 保持同一签名，保证跨平台编译与调用方（Task 9）代码不变。
func (f *Firewall) EnsureProtectedPorts(protected []uint16, spaPort uint16) error {
	return errLinuxOnly
}

// Uninstall 在非 Linux 平台上不可用。
func (f *Firewall) Uninstall() error { return errLinuxOnly }

//go:build linux

// 本文件是附着后端的抽象层：把 knok 的 TC ingress 程序挂到网卡上，并在
// 进程重启/崩溃后能对账（不留无法回收的残留）。
//
// 两种后端（具体实现在 backend_tcx.go / backend_clsact.go）：
//
//   - TCX（内核 ≥ 6.6）：BPF_LINK_CREATE 的 tcx ingress 链接。附着体是内核里的
//     bpf_link 对象，可以 pin 进 bpffs，所以 knokd 崩溃/重启后附着仍然存在
//     （已授权流量不中断），新进程从 pin 复用同一个 link。
//   - clsact 兜底（内核 < 6.6，或 KNOK_FORCE_CLSACT=1）：tc clsact qdisc 上的
//     cls_bpf direct-action filter。filter 天然在进程退出后存活，靠 filter 名字
//     与 (prio, protocol) 对账。
//
// 选择逻辑只依赖 uname，不做能力探测（spec §5.1 的 6.6 分界）。
package ebpfplat

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Handle 是一次成功附着的句柄。
//
// Link 只在 TCX 后端非 nil（真正持有内核 link 的 fd）；clsact 后端的附着体是
// 内核里的 cls_bpf filter，没有 fd 可持有，靠 IfIndex 定位，故为 nil。
type Handle struct {
	IfIndex int
	IfName  string
	Kind    string // "tcx" | "clsact"
	Link    link.Link
}

// AttachBackend 抽象"把程序挂上去 / 摘下来 / 对账"。
type AttachBackend interface {
	// Attach 把 prog 挂到 ifindex 的 ingress；pinDir 是崩溃存活用的 pin 目录
	// （bpffs 下，由调用方决定，Task 9 从配置传入）。
	Attach(ifindex int, prog *ebpf.Program, pinDir string) (Handle, error)
	// Detach 释放本次进程持有的附着句柄。对 TCX 而言 pin 与内核附着不受影响
	// （见 Ruling 5：删除 pin 是 Unpin 的职责）。
	Detach(h Handle) error
	// List 与内核对账，返回当前真实存在的 knok 附着（含崩溃后遗留的）。
	List(pinDir string) ([]Handle, error)
	// Kind 返回后端名："tcx" 或 "clsact"。
	Kind() string
}

// Unpinner 是 AttachBackend 之外的可选扩展：--uninstall（Task 9）用它把 pin
// 也清掉（TCX），或做等价的完整回收（clsact 无 pin，等价于 Detach）。
//
// 刻意不并入 AttachBackend：Task 6 计划冻结了那四个方法的签名，日常路径
// （启动/关闭/对账）不需要 Unpin。
type Unpinner interface {
	Unpin(h Handle, pinDir string) error
}

// ForceClsactEnv 是强制选择 clsact 后端的开关：置 1（或 true）时 DetectBackend
// 忽略内核版本直接返回 clsact。用于在 6.6+ 内核上验证兜底路径。
const ForceClsactEnv = "KNOK_FORCE_CLSACT"

// forceClsact 报告强制开关是否置位。
//
// 只有 "1" 与 "true"（大小写不敏感）算置位；"0"、"yes"、"" 都不算。宽松的
// "非空即真" 会让 KNOK_FORCE_CLSACT=0 意外退回 clsact——测试也必须用同一个
// 判定推导期望值，否则 KNOK_FORCE_CLSACT=0 下期望与实际会分叉。
func forceClsact() bool {
	v := os.Getenv(ForceClsactEnv)
	return v == "1" || strings.EqualFold(v, "true")
}

// tcxSupported 判断内核版本是否支持 TCX：主.次 ≥ 6.6。
//
// release 是 uname 的 release 字段（如 "6.8.0-107-generic"）。解析不出主/次
// 版本（格式不符或非数字）一律视为不支持，退回 clsact——宁可用确定性更强的
// clsact，也不在一个版本未知的内核上试 TCX。
func tcxSupported(release string) bool {
	parts := strings.SplitN(release, ".", 3)
	if len(parts) < 2 {
		return false
	}
	maj, err1 := strconv.Atoi(parts[0])
	min, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return false
	}
	return maj > 6 || (maj == 6 && min >= 6)
}

// kernelRelease 读 uname 的 release 字段（读不到时返回空串，tcxSupported 会
// 把它判为不支持）。
func kernelRelease() string {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return ""
	}
	return strings.TrimRight(string(u.Release[:]), "\x00")
}

// DetectBackend：uname 主.次 ≥ 6.6 → TCX，否则 clsact。
//
// KNOK_FORCE_CLSACT=1 时无条件选 clsact——否则 TCX 可用的内核上，兜底后端
// 永远没有机会被真实内核路径验证。
//
// 两个判定（forceClsact / tcxSupported）刻意与集成测试共用：测试据同一规则
// 推导期望后端，不在测试里重述一遍（重述过的副本会在 <6.6 内核或
// KNOK_FORCE_CLSACT=0 时把正确的选择判成失败）。
func DetectBackend() AttachBackend {
	if forceClsact() {
		return &ClsactBackend{}
	}
	if tcxSupported(kernelRelease()) {
		return &TCXBackend{}
	}
	return &ClsactBackend{}
}

// ResolveInterfaces：M2 仅支持 explicit 模式（auto/reconcile 属 M5）。
//
// 空列表返回空切片而不是错误：调用方（Task 9）用 len==0 判断"没有要保护的
// 接口"，那是配置层面的决策，不该在这一层变成错误。
func ResolveInterfaces(names []string) ([]netlink.Link, error) {
	out := make([]netlink.Link, 0, len(names))
	for _, n := range names {
		l, err := netlink.LinkByName(n)
		if err != nil {
			return nil, fmt.Errorf("interface %s: %w", n, err)
		}
		out = append(out, l)
	}
	return out, nil
}

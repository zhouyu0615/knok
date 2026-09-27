//go:build linux

package ebpfplat

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// TCXBackend 用 BPF_LINK_CREATE 的 tcx ingress 链接挂程序（内核 ≥ 6.6）。
//
// 与 clsact 的关键差别：附着体是内核里的 bpf_link 对象，可以 pin 进 bpffs。
// 所以 knokd 崩溃/重启后附着仍然存在（已授权流量不中断），新进程从 pin 复用
// 同一个 link（见 Attach 的复用分支）；回收 pin 是 Unpin（--uninstall）的事。
type TCXBackend struct{}

var (
	_ AttachBackend = (*TCXBackend)(nil)
	_ Unpinner      = (*TCXBackend)(nil)
)

func (b *TCXBackend) Kind() string { return "tcx" }

// tcxPinPath 是 pin 文件路径：<pinDir>/tcx-<ifindex>。
//
// 一个接口一个 pin，文件名即 ifindex，List 因此不需要读文件内容就能对账。
func tcxPinPath(pinDir string, ifindex int) string {
	return filepath.Join(pinDir, fmt.Sprintf("tcx-%d", ifindex))
}

// Attach 复用已有 pin，否则新建 link 并 pin 之。
//
// 复用而非重新附着是崩溃存活的另一半：knokd 重启时若重新 BPF_LINK_CREATE，
// 内核里的 tcx 链会多出一条（tcx 允许同一 hook 上串多条 link），旧的那条
// 还挂着旧程序与旧 map——既浪费又会让行为取决于 link 顺序。
func (b *TCXBackend) Attach(ifindex int, prog *ebpf.Program, pinDir string) (Handle, error) {
	pinPath := tcxPinPath(pinDir, ifindex)

	if l, err := link.LoadPinnedLink(pinPath, nil); err == nil {
		return Handle{IfIndex: ifindex, IfName: pinName(ifindex), Kind: b.Kind(), Link: l}, nil
	}

	l, err := link.AttachTCX(link.TCXOptions{
		Interface: ifindex,
		Program:   prog,
		Attach:    unix.BPF_TCX_INGRESS,
	})
	if err != nil {
		return Handle{}, fmt.Errorf("attach tcx ifindex=%d: %w", ifindex, err)
	}

	if err := pinLink(l, pinPath, pinDir); err != nil {
		// 不留半挂状态：pin 不上就回收刚建立的 link，Attach 要么完整成功
		// （附着 + 崩溃存活），要么什么都没挂。
		_ = l.Close()
		return Handle{}, err
	}
	return Handle{IfIndex: ifindex, IfName: pinName(ifindex), Kind: b.Kind(), Link: l}, nil
}

// pinLink 把 link 落盘到 bpffs。
//
// 计划草稿在这里写的是 `if os.MkdirAll(pinDir) == nil { _ = l.Pin(pinPath) }`
// ——把 pin 失败静默吞掉，结果是"挂上了但没有崩溃存活能力"的半挂状态，而
// Attach 没有警告通道，调用方无从感知。这里改为失败即报错并回收 link：
// 崩溃存活是 knok 的设计前提（Ruling 5 的 Unpin 回收路径同样依赖 pin 存在）。
//
// 注意 cilium 的 Link.Pin 要求目标目录真的在 bpf 文件系统上（internal/sys/pinning.go
// 会检查 fstype），所以 pinDir 必须是 bpffs 下的目录，否则这里会显式失败。
func pinLink(l link.Link, pinPath, pinDir string) error {
	if err := os.MkdirAll(pinDir, 0o755); err != nil {
		return fmt.Errorf("pin dir %s: %w", pinDir, err)
	}

	err := l.Pin(pinPath)
	// 同名 pin 已存在但加载不了（例如 bpffs 重挂过、上一次非正常退出留下死
	// pin）：能加载的 pin 在上面就被复用分支返回了，走到这里说明它不可用，
	// 删掉死 pin 后重试一次，避免一个残留文件永久挡住重新附着。
	if errors.Is(err, unix.EEXIST) {
		if rerr := os.Remove(pinPath); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
			return fmt.Errorf("pin tcx link %s: %w", pinPath, err)
		}
		err = l.Pin(pinPath)
	}
	if err != nil {
		return fmt.Errorf("pin tcx link %s: %w", pinPath, err)
	}
	return nil
}

// Detach 只释放本进程持有的句柄。
//
// Ruling 5：**不删 pin**。已 pin 的 link 由 bpffs 里的 pin 持有内核引用，
// Close 不会解开附着——这正是"knokd 崩溃/重启后已授权流量不中断"的语义。
// 删除 pin 是 Unpin（--uninstall）的职责；残留的死 pin 由 List/Attach 对账吸收。
func (b *TCXBackend) Detach(h Handle) error {
	if h.Link == nil {
		return nil
	}
	return h.Link.Close()
}

// Unpin 删除 pin 并关闭句柄：--uninstall 的完整回收路径（Task 9）。
//
// 删除 pin 后内核引用归零（前提是这个 link 的其它 fd 都已关闭），附着随之消失。
func (b *TCXBackend) Unpin(h Handle, pinDir string) error {
	pinPath := tcxPinPath(pinDir, h.IfIndex)
	if err := os.Remove(pinPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("unpin %s: %w", pinPath, err)
	}
	if h.Link == nil {
		return nil
	}
	return h.Link.Close()
}

// List 用 pin 目录对账：每个可加载的 tcx-<ifindex> 就是一条仍然生效的附着。
//
// 加载不了的 pin 直接跳过（视为未附着）——它不会让整次对账失败，也不会被
// List 删除（List 是只读的；清理死 pin 由 Attach 的重试或 Unpin 负责）。
func (b *TCXBackend) List(pinDir string) ([]Handle, error) {
	ents, err := os.ReadDir(pinDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil // pin 目录还不存在 = 没有任何附着
		}
		return nil, fmt.Errorf("list pin dir %s: %w", pinDir, err)
	}

	var out []Handle
	for _, e := range ents {
		var idx int
		if _, err := fmt.Sscanf(e.Name(), "tcx-%d", &idx); err != nil {
			continue // 不是本后端的 pin（例如 Task 7 的 map pin）
		}
		l, err := link.LoadPinnedLink(filepath.Join(pinDir, e.Name()), nil)
		if err != nil {
			continue // 死 pin：link 已不存在
		}
		out = append(out, Handle{IfIndex: idx, IfName: pinName(idx), Kind: b.Kind(), Link: l})
	}
	return out, nil
}

// pinName 返回用于日志/句柄展示的接口名：优先真实名字，取不到时退化为
// if<ifindex>（接口可能刚好被删掉，或索引来自一个已经消失的 pin）。
func pinName(ifindex int) string {
	if l, err := netlink.LinkByIndex(ifindex); err == nil {
		return l.Attrs().Name
	}
	return fmt.Sprintf("if%d", ifindex)
}

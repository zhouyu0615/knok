//go:build linux

package ebpfplat

import (
	"errors"
	"fmt"
	"log/slog"
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
//
// 复用有一个必须处理的例外（final review finding E）：pin 里的 link 挂着的是
// **上一个进程加载的程序**（程序不 pin，每次启动都是一次新的 bpf_prog_load，
// 因此 id 必然不同）。升级之后新进程写的 map 由新程序语义解释，而内核里跑的
// 可能还是旧程序——旧程序的行为、旧 ABI 的解读都不会有任何日志。所以复用前先
// 比程序 id：一致才原样复用；不一致时**原地换程序**（BPF_LINK_UPDATE：pin 与
// 附着都不中断，也不存在"网卡上没有 knok 程序"的窗口——那个窗口里已授权流量
// 拿不到 mark，会被 nftables 的 drop 规则丢掉）；原地替换不可用时才删 pin 重建。
func (b *TCXBackend) Attach(ifindex int, prog *ebpf.Program, pinDir string) (Handle, error) {
	pinPath := tcxPinPath(pinDir, ifindex)

	pinned, loadErr := link.LoadPinnedLink(pinPath, nil)
	switch {
	case loadErr == nil:
		h := Handle{IfIndex: ifindex, IfName: pinName(ifindex), Kind: b.Kind(), Link: pinned}
		curID, haveCur := linkProgramID(pinned)
		newID, haveNew := programID(prog)
		if haveCur && haveNew && curID == newID {
			return h, nil // 同一程序的 pin：原样复用
		}
		if !haveCur || !haveNew {
			// 读不出任一侧的程序 id（ObjInfo 不可用）：无法判断漂移。保守地保留
			// pin 并告警——"看不见"不等于"该删"，删错会中断生效中的附着。
			slog.Warn("could not read a program id (pinned link or current program); keeping the pinned link as-is",
				"iface", h.IfName, "pin", pinPath,
				"have_pinned_id", haveCur, "have_current_id", haveNew)
			return h, nil
		}
		if uerr := pinned.Update(prog); uerr == nil {
			slog.Warn("pinned tcx link carried a different program id; replaced the kernel program in place (pinned grants untouched)",
				"iface", h.IfName, "pin", pinPath,
				"pinned_prog_id", uint32(curID), "current_prog_id", uint32(newID))
			return h, nil
		} else {
			slog.Warn("pinned tcx link carries a different program and cannot be updated in place; replacing the pin",
				"iface", h.IfName, "pin", pinPath,
				"pinned_prog_id", uint32(curID), "current_prog_id", uint32(newID), "err", uerr)
		}
		// 链上的程序对不上且换不掉：删 pin（这个 link 的内核引用归零，旧附着随之
		// 消失）再重建。这条 pin 刚刚加载成功过，所以这里是"替换一条活的 pin"，
		// 而不是"清理死 pin"——上面的 warn 已经把这件事说出去了。
		if rerr := os.Remove(pinPath); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
			_ = pinned.Close()
			return Handle{}, fmt.Errorf("replace pinned tcx link %s: %w", pinPath, rerr)
		}
		_ = pinned.Close()
	case !pinUnusable(loadErr):
		// 环境/瞬时错误（EMFILE/ENOMEM/EACCES…）：pin 很可能是一条**仍然生效的
		// live link**。绝不能走"新建 + 覆盖同名 pin"的路径（那会先删掉它），
		// 原样返回错误让调用方（knokd）大声失败。
		return Handle{}, fmt.Errorf("load pinned tcx link %s (transient failure, pin left intact): %w", pinPath, loadErr)
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

// linkProgramID 读出一条 link 当前挂载的程序 id。ok=false 表示读不出来
// （Info 不可用）——调用方必须据此保守处理，不能把"看不见"当作"可删除/可替换"。
func linkProgramID(l link.Link) (ebpf.ProgramID, bool) {
	info, err := l.Info()
	if err != nil {
		return 0, false
	}
	return info.Program, true
}

// programID 读出一个已加载程序的 id。cilium/ebpf v0.17 没有 Program.ID()，
// 只能走 Info()（同一份内核对象元数据，代价是一次 bpf_prog_get_info_by_fd）。
func programID(prog *ebpf.Program) (ebpf.ProgramID, bool) {
	info, err := prog.Info()
	if err != nil {
		return 0, false
	}
	return info.ID()
}

// pinUnusable 报告"加载 pin 失败"是否说明 pin 确实不可用（因此可以重建）。
//
// 只有这种情况才允许走"新建 link 并覆盖同名 pin"的路径。EMFILE/ENFILE/ENOMEM/
// EACCES/EPERM/EROFS/EBUSY 是环境或瞬时错误：pin 很可能是一条**仍然生效的 live
// link**（另一个 knokd 用光了 fd，或本进程读不了 bpffs），删掉它就是中断一条正在
// 工作的附着——升级时那意味着已授权流量立刻全部落到 drop 规则上。
// ENOENT（没有 pin）与"pin 内容确实坏掉"归为可重建：前者根本不存在，后者重建是
// 唯一出路。
func pinUnusable(err error) bool {
	transient := []error{unix.EMFILE, unix.ENFILE, unix.ENOMEM, unix.EACCES, unix.EPERM, unix.EROFS, unix.EBUSY}
	for _, e := range transient {
		if errors.Is(err, e) {
			return false
		}
	}
	return true
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
	//
	// 删除之前**再确认一次**这条 pin 确实不可用（finding E 的另一半）：EEXIST
	// 也可能来自"另一个进程刚建立了一条 live pin"（竞态）或"上面那次加载失败
	// 是瞬时错误"。删掉别人的生效附着，比多报一个错误糟得多。
	if errors.Is(err, unix.EEXIST) {
		if _, lerr := link.LoadPinnedLink(pinPath, nil); lerr == nil || !pinUnusable(lerr) {
			return fmt.Errorf("pin tcx link %s: %w (an existing usable pin was left intact)", pinPath, err)
		}
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

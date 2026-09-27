//go:build linux && integration

// 本文件只在 Linux + integration 标签下编译，且必须对真实内核、以 root 运行
// （Attach/detach/filter 枚举都需要 CAP_NET_ADMIN/CAP_BPF）：
//
//	sudo -E go test -tags=integration -count=1 -run TestAttachDetachLoopback ./internal/platform/ebpf/ -v
//	sudo -E KNOK_FORCE_CLSACT=1 go test -tags=integration -count=1 -run TestAttachDetachLoopback ./internal/platform/ebpf/ -v
//
// 前置条件：bpffs 已挂载在 /sys/fs/bpf（TCX 的 link pin 与四张 map 的
// PinByName pin 都只能落在 bpf 文件系统上，cilium 会检查目标目录的 fstype），
// 且 lo 存在。
//
// pin 目录由 ebpfplat.TestPinDir 提供：/sys/fs/bpf/knok-it-<测试名>，与
// daemon 自己的 pin 目录（Task 9 从配置传入）分开，用例结束即整目录删除——
// 上一次失败运行的残留会在加载前被吸收。

package ebpfplat_test

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	ebpfplat "github.com/zhouyu0615/knok/internal/platform/ebpf"
)

// TestAttachDetachLoopback 在真实内核上跑完整生命周期，两种后端共用同一段
// 用例体（由 DetectBackend 依内核版本或 KNOK_FORCE_CLSACT=1 选择）：
//
//	Attach（+ 后端选择与 Handle 字段）
//	  → List 必须看得见
//	  → 再次 Attach：TCX 复用同一个 link / clsact 替换而非叠加
//	  → Detach：TCX 的 pin 与内核附着仍在（崩溃存活语义），clsact 立即消失
//	  → TCX 走 Unpin（--uninstall 路径）完整回收
//	  → 收尾：List 空、内核里没有 knok filter、没有 knok tcx link、没有 tcx-* pin
//
// clsact 那一轮还会把用例自己建的 clsact qdisc 删掉（lo 本来没有），跑完机器
// 状态与跑之前一致。
func TestAttachDetachLoopback(t *testing.T) {
	// MustLoadForTest 会先清空 pin 目录、再用它作为 map 的 PinPath 加载对象。
	objs := ebpfplat.MustLoadForTest(t)

	lo, err := netlink.LinkByName("lo")
	if err != nil {
		t.Skipf("no loopback: %v", err)
	}
	ifindex := lo.Attrs().Index

	pinDir := ebpfplat.TestPinDir(t)
	be := ebpfplat.DetectBackend()
	kind := be.Kind()
	t.Logf("backend=%s kernel=%s ifindex=%d pinDir=%s", kind, kernelRelease(t), ifindex, pinDir)

	// DetectBackend 的选择必须与预期一致。期望值由实现自身的两个判定推导
	// （见 expectedBackendKindFor），不在测试里重述：重述过的副本会把
	// "<6.6 内核 → tcx"（正确结果被判成失败）与 "KNOK_FORCE_CLSACT 非空即强制"
	// （=0/=yes 时期望与实际分叉）两条 bug 带回来。
	want := expectedBackendKindFor(kernelRelease(t))
	forced := ebpfplat.ForceClsactForTest()
	if kind != want {
		t.Fatalf("DetectBackend() = %s, want %s (kernel %s, %s=%q)",
			kind, want, kernelRelease(t), ebpfplat.ForceClsactEnv, os.Getenv(ebpfplat.ForceClsactEnv))
	}
	t.Logf("backend selection ok: %s (forced=%v)", kind, forced)

	// 基线：吸收上一次失败运行的残留（clsact filter / 死 pin），并记录系统里
	// 的 tcx link 总数（后续用它的增减判断"附着有没有叠加/泄漏"）。
	detachAll(be, ifindex, pinDir)
	// 用例只回收自己建的东西：clsact qdisc 若是本来就在的（别的工具/别的 knok
	// 实例建的），跑完也不动它——backend 的 Detach/Unpin 同理不删 qdisc，它是
	// 共享基础设施；这里的 QdiscDel 纯粹是为了让机器状态与跑之前一致。
	hadClsactQdisc := hasClsactQdisc(t, ifindex)
	t.Cleanup(func() {
		detachAll(be, ifindex, pinDir)
		if !hadClsactQdisc {
			removeClsactQdisc(ifindex)
		}
	})
	baseLinks := countTCXLinks(t)

	// ---- 1) Attach ----
	h1, err := be.Attach(ifindex, objs.KnokIngress, pinDir)
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if h1.IfIndex != ifindex || h1.Kind != kind {
		t.Fatalf("Handle = %+v, want IfIndex=%d Kind=%s", h1, ifindex, kind)
	}
	if want := lo.Attrs().Name; h1.IfName != want {
		t.Fatalf("Handle.IfName = %q, want %q", h1.IfName, want)
	}
	if kind == "tcx" {
		if _, err := os.Stat(ebpfplat.TCXPinPathForTest(pinDir, ifindex)); err != nil {
			t.Fatalf("Attach 后 pin 应该存在: %v", err)
		}
		if n := countTCXLinks(t); n != baseLinks+1 {
			t.Fatalf("Attach 后 tcx link 数 = %d, want %d", n, baseLinks+1)
		}
	} else if !hasClsactQdisc(t, ifindex) {
		t.Fatalf("Attach 后 lo 上应该存在 clsact qdisc")
	}
	t.Logf("attached: ifindex=%d ifname=%s kind=%s", h1.IfIndex, h1.IfName, h1.Kind)

	// ---- 2) List 必须看得见 ----
	if n := countListed(t, be, pinDir, ifindex); n != 1 {
		t.Fatalf("List 找到 %d 个 knok 附着, want 1", n)
	}
	t.Logf("List ok: 1 attachment on ifindex=%d", ifindex)

	// ---- 3) 再次 Attach：TCX 复用 pinned link；clsact 替换而非叠加 ----
	h2, err := be.Attach(ifindex, objs.KnokIngress, pinDir)
	if err != nil {
		t.Fatalf("second Attach: %v", err)
	}
	var tcxID link.ID
	if kind == "tcx" {
		id1, id2 := linkID(t, h1), linkID(t, h2)
		tcxID = id1
		if id1 != id2 {
			t.Fatalf("第二次 Attach 新建了 link（id %d → %d），应当复用 pin 里的同一个 link", id1, id2)
		}
		if n := countTCXLinks(t); n != baseLinks+1 {
			t.Fatalf("第二次 Attach 后 tcx link 数 = %d, want %d（附着叠加了）", n, baseLinks+1)
		}
		t.Logf("second Attach reused pinned link id=%d (no stacking)", id1)
	} else {
		// 第二次 Attach 先命中 QdiscAdd 的 EEXIST 分支，再走 removeStale +
		// FilterAdd：同位置的旧 knok filter 被替换，而不是叠加出第二个。
		if n := countKnokFilters(t, ifindex); n != 1 {
			t.Fatalf("第二次 Attach 后 knok filter 数 = %d, want 1（旧 filter 没被替换掉）", n)
		}
		t.Logf("second Attach replaced the stale filter (still 1 knok filter)")
	}
	if n := countListed(t, be, pinDir, ifindex); n != 1 {
		t.Fatalf("第二次 Attach 后 List 找到 %d 个, want 1", n)
	}

	// ---- 4) Detach：两个句柄指向同一个附着，逐句柄释放 ----
	for i, h := range []ebpfplat.Handle{h1, h2} {
		if err := be.Detach(h); err != nil {
			t.Fatalf("Detach(#%d): %v", i+1, err)
		}
	}
	if kind == "tcx" {
		// Ruling 5：Detach 只 close 句柄，不删 pin —— pin 还持有内核里的附着，
		// 这正是"knokd 崩溃/重启后已授权流量不中断"的语义；删 pin 是 Unpin 的事。
		if _, err := os.Stat(ebpfplat.TCXPinPathForTest(pinDir, ifindex)); err != nil {
			t.Fatalf("Detach 不得删除 pin: %v", err)
		}
		if n := countListed(t, be, pinDir, ifindex); n != 1 {
			t.Fatalf("Detach 后 List 找到 %d 个, want 1（附着由 pin 持有，仍在生效）", n)
		}
		if n := countTCXLinks(t); n != baseLinks+1 {
			t.Fatalf("Detach 后 tcx link 数 = %d, want %d（附着不应被解开）", n, baseLinks+1)
		}
		t.Logf("Detach left the pinned attachment alive (crash-survival semantics)")
	} else {
		// clsact：filter 就是附着体，Detach 直接删掉它。
		if n := countListed(t, be, pinDir, ifindex); n != 0 {
			t.Fatalf("clsact Detach 后 List 找到 %d 个, want 0", n)
		}
		if n := countKnokFilters(t, ifindex); n != 0 {
			t.Fatalf("clsact Detach 后 knok filter 数 = %d, want 0", n)
		}
		t.Logf("Detach removed the cls_bpf filter")
	}

	// ---- 5) 完整回收：TCX 删 pin（--uninstall 路径）；clsact 无 pin ----
	if kind == "tcx" {
		unp, ok := be.(ebpfplat.Unpinner)
		if !ok {
			t.Fatalf("%T 未实现 ebpfplat.Unpinner", be)
		}
		hs, err := be.List(pinDir)
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(hs) != 1 {
			t.Fatalf("Unpin 前 List 返回 %d 个句柄, want 1", len(hs))
		}
		for _, h := range hs {
			if err := unp.Unpin(h, pinDir); err != nil {
				t.Fatalf("Unpin: %v", err)
			}
		}
		if _, err := os.Stat(ebpfplat.TCXPinPathForTest(pinDir, ifindex)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("Unpin 后 pin 应该消失, got err=%v", err)
		}
		t.Logf("Unpin removed the pin")
	}

	// ---- 6) 收尾：不留任何残留 ----
	if n := countListed(t, be, pinDir, ifindex); n != 0 {
		t.Fatalf("收尾后 List 找到 %d 个, want 0", n)
	}
	if n := countKnokFilters(t, ifindex); n != 0 {
		t.Fatalf("收尾后 knok filter 数 = %d, want 0", n)
	}
	if kind == "tcx" {
		// 不只是 pin 文件没了：内核里的 link 对象也必须真的释放（否则就是一个
		// 看不见但仍在生效的附着）。内核释放 bpf_link 可能经 RCU/工作队列延后，
		// 所以轮询给一小段宽限期。
		waitLinkGone(t, tcxID, 3*time.Second)
		if n := countTCXLinks(t); n != baseLinks {
			t.Fatalf("收尾后 tcx link 数 = %d, want %d", n, baseLinks)
		}
	}
	// pin 目录里剩下的只能是本次加载的四张 map 的 pin（PinByName），不能再有
	// tcx-* ——那就是没回收掉的 link 附着。
	for _, e := range readDirNames(t, pinDir) {
		if strings.HasPrefix(e, "tcx-") {
			t.Fatalf("pin 目录残留附着 pin: %s", e)
		}
	}
	t.Logf("clean: no knok attachment, no filter, no link, no tcx-* pin (left: %v)", readDirNames(t, pinDir))
}

// readDirNames 列出目录里的条目名（目录不存在时返回 nil）。
func readDirNames(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		t.Fatalf("read pin dir %s: %v", dir, err)
	}
	names := make([]string, 0, len(ents))
	for _, e := range ents {
		names = append(names, e.Name())
	}
	return names
}

// detachAll 吸收上一次（可能失败的）运行留下的残留：先删接口上的 knok
// filter，再把 pin 目录里的每个 pin 都 Unpin 掉。用例必须可重复执行。
func detachAll(be ebpfplat.AttachBackend, ifindex int, pinDir string) {
	_ = be.Detach(ebpfplat.Handle{IfIndex: ifindex})
	unp, ok := be.(ebpfplat.Unpinner)
	if !ok {
		return
	}
	hs, err := be.List(pinDir)
	if err != nil {
		return
	}
	for _, h := range hs {
		_ = unp.Unpin(h, pinDir)
	}
}

// countListed 数 List 在 ifindex 上看到的 knok 附着，并关掉 List 借出的 fd。
//
// 关 fd 是必须的：pin 之外的每个打开 fd 都是内核 link 的一份引用，留着会让
// 收尾的"link 已释放"断言失败（那将是测试自己的泄漏）。
func countListed(t *testing.T, be ebpfplat.AttachBackend, pinDir string, ifindex int) int {
	t.Helper()
	hs, err := be.List(pinDir)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	var n int
	for _, h := range hs {
		if h.IfIndex == ifindex {
			n++
		}
		if h.Link != nil {
			if err := h.Link.Close(); err != nil {
				t.Fatalf("close listed handle: %v", err)
			}
		}
	}
	return n
}

// countKnokFilters 直接问内核（等价于 `tc filter show dev lo ingress`）该接口
// ingress 上有几个名为 knok 的 cls_bpf filter。独立于 AttachBackend.List 实现，
// 避免"自己的代码验证自己"。
//
// 没有 clsact qdisc 的接口枚举不到东西（内核返回空/ENOENT），对 TCX 那一轮
// 来说这是预期情况，故容忍错误并记为 0。
func countKnokFilters(t *testing.T, ifindex int) int {
	t.Helper()
	l, err := netlink.LinkByIndex(ifindex)
	if err != nil {
		t.Fatalf("link ifindex=%d: %v", ifindex, err)
	}
	filters, err := netlink.FilterList(l, netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		t.Logf("filter list ifindex=%d: %v（无 clsact qdisc 时属预期）", ifindex, err)
		return 0
	}
	var n int
	for _, f := range filters {
		if bf, ok := f.(*netlink.BpfFilter); ok && bf.Name == ebpfplat.KnokFilterNameForTest {
			n++
		}
	}
	return n
}

// hasClsactQdisc 判断接口上是否挂着 clsact qdisc。
func hasClsactQdisc(t *testing.T, ifindex int) bool {
	t.Helper()
	l, err := netlink.LinkByIndex(ifindex)
	if err != nil {
		t.Fatalf("link ifindex=%d: %v", ifindex, err)
	}
	qdiscs, err := netlink.QdiscList(l)
	if err != nil {
		t.Fatalf("qdisc list ifindex=%d: %v", ifindex, err)
	}
	for _, q := range qdiscs {
		if _, ok := q.(*netlink.Clsact); ok {
			return true
		}
	}
	return false
}

// removeClsactQdisc 删掉接口上的 clsact qdisc（测试收尾用，best-effort）。
func removeClsactQdisc(ifindex int) {
	_ = netlink.QdiscDel(&netlink.Clsact{QdiscAttrs: netlink.QdiscAttrs{
		LinkIndex: ifindex,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}})
}

// linkID 取内核 bpf_link 的 id：两次 Attach 拿到同一个 id 就证明是同一个 link
// （没有新建、没有叠加）。
func linkID(t *testing.T, h ebpfplat.Handle) link.ID {
	t.Helper()
	if h.Link == nil {
		t.Fatalf("Handle.Link 为 nil，取不到 link id")
	}
	info, err := h.Link.Info()
	if err != nil {
		t.Fatalf("link info: %v", err)
	}
	return info.ID
}

// countTCXLinks 数全系统的 tcx link 数（所有接口、所有程序）。
//
// 用增减量（而不是绝对值）判断附件身份的成立：一开始记基线，Attach 后 +1，
// 第二次 Attach 后仍 +1（复用而非叠加），Unpin 后回到基线（真的释放了）。
func countTCXLinks(t *testing.T) int {
	t.Helper()
	var it link.Iterator
	var n int
	var infoErr error
	for it.Next() {
		info, err := it.Link.Info()
		if err != nil {
			infoErr = err
			break
		}
		if info.Type == link.TCXType {
			n++
		}
	}
	it.Close()
	if err := it.Err(); err != nil {
		t.Fatalf("iterate links: %v", err)
	}
	if infoErr != nil {
		t.Fatalf("link info: %v", infoErr)
	}
	return n
}

// waitLinkGone 轮询直到 id 对应的内核 link 真的消失（Unpin 之后）。
func waitLinkGone(t *testing.T, id link.ID, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		l, err := link.NewFromID(id)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return
			}
			t.Fatalf("NewFromID(%d): %v", id, err)
		}
		_ = l.Close()
		if time.Now().After(deadline) {
			t.Fatalf("Unpin 后 link id=%d 仍然存在：附着没被释放", id)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// kernelRelease 读内核版本，用于日志与后端选择的报错信息。
func kernelRelease(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		t.Fatalf("read osrelease: %v", err)
	}
	return strings.TrimSpace(string(b))
}

// expectedBackendKindFor 推导给定内核版本（release）下 DetectBackend 应当选出的
// 后端，规则与 backend.go 完全同源：先问强制开关（ForceClsactForTest），再用
// 6.6 分界（TCXSupportedForTest）。两个判定都取自实现，本函数只做组合，因此
// 测试不会在实现改规则时继续断言旧规则，也不会在 <6.6 内核上把正确的 clsact
// 判成失败。
//
// release 是参数而不是直接读内核，这样"期望是否跟着判定走"可以在没有 <6.6
// 内核的机器上用合成版本号验证。
func expectedBackendKindFor(release string) string {
	if ebpfplat.ForceClsactForTest() {
		return "clsact"
	}
	if ebpfplat.TCXSupportedForTest(release) {
		return "tcx"
	}
	return "clsact"
}

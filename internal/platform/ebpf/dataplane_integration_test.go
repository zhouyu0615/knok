//go:build linux && integration

// 本文件是 Task 7 的数据面端到端用例，必须在真实内核上以 root 运行
// （加载 BPF、attach lo、读写 map 都需要 CAP_NET_ADMIN/CAP_BPF）：
//
//	sudo -E go test -tags=integration -count=1 -run TestDataplaneRoundTrip ./internal/platform/ebpf/ -v
//
// 它验证的是一条**内核里的**通路，而不是 Go 侧的模拟：加载 map（生产路径
// LoadObjects）→ 在 lo 上 attach（Task 6 的后端）→ 写 cfg → magic UDP 包经 TC
// ingress 上送 ringbuf → RingbufSource 解析成 CandidatePacket → MapAllowlist 授权
// 另一个端口 → 该端口的包在内核里命中 allowlist 并打标（stats ST_ALLOW_HIT 递增）
// → 未授权端口不命中 → 过期授权命中后被内核删除（ST_ALLOW_EXPIRY）→ List/Revoke
// 往返 → 收尾不留残留。
//
// 前置条件：bpffs 已挂载在 /sys/fs/bpf（map 的 PinByName pin 与 TCX link pin 都
// 只能落在 bpf 文件系统上），lo 存在。pin 目录由 ebpfplat.TestPinDir 提供
// （/sys/fs/bpf/knok-it-<测试名>），用例结束整目录删除。
package ebpfplat_test

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"github.com/zhouyu0615/knok/internal/core/ports"
	"github.com/zhouyu0615/knok/internal/core/testfakes"
	ebpfplat "github.com/zhouyu0615/knok/internal/platform/ebpf"
)

// 用例端口：SPA 端口刻意与授权端口不同——SPA 端口自身若被授权，候选包会先在
// allowlist 命中（打标并放行）、根本进不了 ringbuf，上送通路就验不到了。
const (
	itSPAPort     = 14242 // cfg.spa_port：只有发往它的 magic 包才上送
	itGrantPort   = 9999  // 正常授权（带 TTL）的业务端口 → 打标路径
	itOtherPort   = 9998  // 未授权且非 SPA 的端口 → 负例
	itExpiredPort = 9997  // 授权过、TTL 已过 → 内核判定过期并删除
	itZeroPort    = 9996  // ttl <= 0 的授权 → List 必须不展示
	itForeverPort = 9995  // GrantForever → List 的 Forever 分支
)

func TestDataplaneRoundTrip(t *testing.T) {
	// MustLoadForTest 走生产路径 LoadObjects（pin 目录 + PinByName 复用），并在
	// 测试结束时 Close 对象、删掉 pin 目录。
	objs := ebpfplat.MustLoadForTest(t)

	lo, err := netlink.LinkByName("lo")
	if err != nil {
		t.Skipf("no loopback: %v", err)
	}
	ifindex := lo.Attrs().Index

	// Attach 的 pin 目录与加载用的目录是同一个（TestPinDir 按测试名隔离）：
	// TCX 的 tcx-<ifindex> link pin 与四张 map 的 pin 共处一处，与 knokd 的
	// 真实布局一致，收尾时整目录回收。
	pinDir := ebpfplat.TestPinDir(t)
	be := ebpfplat.DetectBackend()
	t.Logf("backend=%s kernel=%s ifindex=%d pinDir=%s", be.Kind(), kernelRelease(t), ifindex, pinDir)

	// 基线：吸收上一次失败运行的残留（clsact filter / 死 pin），并记下 tcx link
	// 总数——收尾时用它的增减证明附着真的被释放了（而不是只删了 pin 文件）。
	detachAll(be, ifindex, pinDir)
	hadClsactQdisc := hasClsactQdisc(t, ifindex)
	t.Cleanup(func() {
		detachAll(be, ifindex, pinDir)
		if !hadClsactQdisc {
			removeClsactQdisc(ifindex)
		}
	})
	baseLinks := countTCXLinks(t)

	h, err := be.Attach(ifindex, objs.KnokIngress, pinDir)
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}
	var tcxLinkID link.ID
	if be.Kind() == "tcx" {
		tcxLinkID = linkID(t, h)
	}
	t.Logf("attached: ifindex=%d ifname=%s kind=%s", h.IfIndex, h.IfName, h.Kind)

	if err := ebpfplat.WriteCfg(objs, itSPAPort, 46, 512); err != nil {
		t.Fatalf("WriteCfg: %v", err)
	}

	src, err := ebpfplat.NewRingbufSource(objs.SpaEvents, 16)
	if err != nil {
		t.Fatalf("NewRingbufSource: %v", err)
	}
	defer src.Close()

	// ---- 1) 候选包通路：magic UDP 包 → ringbuf 事件 ----
	spa := append([]byte("KNOK"), make([]byte, 60)...) // 64 字节，落在 [46,512] 内
	sendUDP(t, itSPAPort, spa)
	pkt := waitEvent(t, src, 3*time.Second)

	if len(pkt.Payload) < 4 {
		t.Fatalf("事件载荷只有 %d 字节，无法包含 magic", len(pkt.Payload))
	}
	if got := string(pkt.Payload[:4]); got != "KNOK" {
		t.Fatalf("载荷前 4 字节 = %q, want %q（C 侧 magic 过滤/偏移解析）", got, "KNOK")
	}
	if pkt.DstPort != itSPAPort {
		t.Fatalf("DstPort = %d, want %d", pkt.DstPort, itSPAPort)
	}
	if !pkt.SrcIP.IsLoopback() {
		t.Fatalf("SrcIP = %v, want 回环地址", pkt.SrcIP)
	}
	if pkt.IfIndex != ifindex {
		t.Fatalf("IfIndex = %d, want %d (lo)", pkt.IfIndex, ifindex)
	}
	if len(pkt.Payload) != len(spa) {
		t.Fatalf("载荷长度 = %d, want %d（min/max 长度校验应放行完整载荷）", len(pkt.Payload), len(spa))
	}
	t.Logf("ringbuf 事件: src=%v dst_port=%d ifindex=%d payload=%d 字节 (前 4 字节 KNOK)",
		pkt.SrcIP, pkt.DstPort, pkt.IfIndex, len(pkt.Payload))

	allowedBy := netip.MustParseAddr("127.0.0.1")
	al := ebpfplat.NewMapAllowlist(objs.Allowlist, testfakes.NewFakeClock(time.Now()))
	base := readStats(t, objs)

	// ---- 2) 打标通路：Grant 另一个端口 → 该端口流量在内核命中 allowlist ----
	if err := al.Grant(allowedBy, itGrantPort, 30*time.Second); err != nil {
		t.Fatalf("Grant(%v:%d): %v", allowedBy, itGrantPort, err)
	}

	// List 能读回刚写的 key：证明 Go 侧的 key 编码与 C 侧布局一致（v4-mapped）。
	entries, err := al.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("Grant 后 List = %+v, want 恰好 1 条", entries)
	}
	if e := entries[0]; e.IP != allowedBy || e.Port != itGrantPort {
		t.Fatalf("List[0] = %+v, want {%v %d}", e, allowedBy, itGrantPort)
	} else if e.Forever || e.ExpiresAt.IsZero() {
		t.Fatalf("带 TTL 的授权应有 ExpiresAt 且不能是 Forever: %+v", e)
	}

	// 幂等性：重复 Grant 是覆盖（仍只有 1 条），Revoke 不存在的 key 不算失败。
	if err := al.Grant(allowedBy, itGrantPort, 30*time.Second); err != nil {
		t.Fatalf("重复 Grant: %v", err)
	}
	if err := al.Revoke(allowedBy, itOtherPort); err != nil {
		t.Fatalf("Revoke 不存在的 key 必须幂等（返回 nil）: %v", err)
	}
	if entries, err = al.List(); err != nil || len(entries) != 1 {
		t.Fatalf("重复 Grant/Revoke 不存在项后 List = %+v (err=%v), want 1 条", entries, err)
	}

	// 发往已授权端口的普通 UDP（不含 magic，无需是 SPA）：内核命中 → 打
	// skb->mark → ST_ALLOW_HIT 递增。这一步就是 mark 通路的端到端证明。
	sendUDP(t, itGrantPort, []byte("no-magic-here"))
	hit := waitStatAtLeast(t, objs, ebpfplat.StAllowHit, base[ebpfplat.StAllowHit]+1, 3*time.Second,
		"授权端口命中 allowlist（内核应打 skb->mark）")
	t.Logf("mark 通路: allow_hit %d → %d（端口 %d 在内核命中并打标）",
		base[ebpfplat.StAllowHit], hit[ebpfplat.StAllowHit], itGrantPort)

	// ---- 3) 负例：未授权且非 SPA 的端口不得命中 ----
	beforeNeg := readStats(t, objs)
	sendUDP(t, itOtherPort, []byte("no-magic-here"))
	// 先等 TOTAL 前进，证明 hook 确实还在处理 lo 上的包（否则"没命中"可能只是
	// 包根本没到 hook）。TOTAL 与 allowlist 判定在同一次 hook 执行里（TOTAL 在前），
	// 所以看到包就意味着本次的 allow_hit 判定已完成；额外沉降只为覆盖观测到的
	// TOTAL 增量来自其它 loopback 流量的情况。
	total := waitStatAtLeast(t, objs, ebpfplat.StTotal, beforeNeg[ebpfplat.StTotal]+1, 3*time.Second,
		"hook 仍在处理 lo 流量")
	time.Sleep(200 * time.Millisecond)
	afterNeg := readStats(t, objs)
	if afterNeg[ebpfplat.StAllowHit] != beforeNeg[ebpfplat.StAllowHit] {
		t.Fatalf("未授权端口 %d 命中了 allowlist: allow_hit %d → %d",
			itOtherPort, beforeNeg[ebpfplat.StAllowHit], afterNeg[ebpfplat.StAllowHit])
	}
	t.Logf("负例: 端口 %d 未命中（allow_hit 保持 %d；total %d → %d 证明 hook 活着）",
		itOtherPort, afterNeg[ebpfplat.StAllowHit], beforeNeg[ebpfplat.StTotal], total[ebpfplat.StTotal])

	// ---- 4) 过期授权：内核命中但判定过期 → 删除 + ST_ALLOW_EXPIRY，不打标 ----
	// TTL 用 1ns（真实的正 TTL，只是授权时刻早已过去）：写入后再发包，中间隔着
	// 系统调用与 lo 收发，单调时钟必然越过 t0+1ns。
	// 同时写一条 ttl=0 的授权：它必须同样被 List 视为已过期（严格约定 now < expiry）。
	beforeExp := readStats(t, objs)
	if err := al.Grant(allowedBy, itExpiredPort, time.Nanosecond); err != nil {
		t.Fatalf("Grant(%d, 1ns): %v", itExpiredPort, err)
	}
	if err := al.Grant(allowedBy, itZeroPort, 0); err != nil {
		t.Fatalf("Grant(%d, 0): %v", itZeroPort, err)
	}
	if entries, err = al.List(); err != nil || len(entries) != 1 {
		t.Fatalf("过期授权不得出现在 List 里: %+v (err=%v), want 1 条（仅 %d）", entries, err, itGrantPort)
	}

	sendUDP(t, itExpiredPort, []byte("no-magic-here"))
	exp := waitStatAtLeast(t, objs, ebpfplat.StAllowExpiry, beforeExp[ebpfplat.StAllowExpiry]+1, 3*time.Second,
		"过期授权命中后被内核删除")
	if exp[ebpfplat.StAllowHit] != beforeExp[ebpfplat.StAllowHit] {
		t.Fatalf("过期授权被打标了: allow_hit %d → %d",
			beforeExp[ebpfplat.StAllowHit], exp[ebpfplat.StAllowHit])
	}
	t.Logf("过期分支: allow_expiry %d → %d（key 命中→判定过期→删除；allow_hit 未动）",
		beforeExp[ebpfplat.StAllowExpiry], exp[ebpfplat.StAllowExpiry])

	// ---- 5) GrantForever / Revoke 往返 ----
	if err := al.GrantForever(allowedBy, itForeverPort); err != nil {
		t.Fatalf("GrantForever: %v", err)
	}
	if entries, err = al.List(); err != nil {
		t.Fatalf("List: %v", err)
	}
	var forever *ports.Entry
	for i := range entries {
		if entries[i].Port == itForeverPort {
			forever = &entries[i]
		}
	}
	if forever == nil {
		t.Fatalf("GrantForever 后 List 里没有端口 %d: %+v", itForeverPort, entries)
	}
	if !forever.Forever || !forever.ExpiresAt.IsZero() {
		t.Fatalf("Forever 条目形态不对: %+v", *forever)
	}

	for _, e := range entries {
		if err := al.Revoke(e.IP, e.Port); err != nil {
			t.Fatalf("Revoke(%v:%d): %v", e.IP, e.Port, err)
		}
	}
	if entries, err = al.List(); err != nil || len(entries) != 0 {
		t.Fatalf("Revoke 后 List = %+v (err=%v), want 空", entries, err)
	}
	for _, p := range []uint16{itGrantPort, itExpiredPort, itZeroPort, itForeverPort} {
		if err := al.Revoke(allowedBy, p); err != nil {
			t.Fatalf("重复 Revoke(%d) 必须幂等: %v", p, err)
		}
	}
	t.Logf("allowlist 往返: Grant/GrantForever/List/Revoke 一致（含重复撤销幂等）")

	// ---- 6) 慢消费：丢弃并计数，而非阻塞内核 reader ----
	// 先关掉第一个 source（两个 reader 会抢同一个 ringbuf，也会让事件归属不确定），
	// 再用容量 0 的 channel 起第二个：本用例始终不读它的通道，因此每个事件都只能
	// 走 default 分支 → 发几个就丢几个。
	if err := src.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := src.Close(); err != nil {
		t.Fatalf("Close 必须幂等: %v", err)
	}
	src2, err := ebpfplat.NewRingbufSource(objs.SpaEvents, 0)
	if err != nil {
		t.Fatalf("NewRingbufSource(buf=0): %v", err)
	}
	defer src2.Close()

	beforeDrop := readStats(t, objs)
	const dropN = 5
	for i := 0; i < dropN; i++ {
		sendUDP(t, itSPAPort, spa)
	}
	// 全部丢弃（不是"丢一部分"）：容量 0 且无人接收，send 只可能走 default。
	waitFor(t, 3*time.Second, func() bool { return src2.Dropped.Load() == dropN },
		"消费方不读时事件应被丢弃并计入 Dropped")
	dropped := src2.Dropped.Load()

	afterDrop := readStats(t, objs)
	// 内核侧的证据：这 5 个包都通过了 magic/长度过滤并提交（candidate +5），
	// 且没有一个是内核 ringbuf 保留失败（ringbuf_drop 不动）——丢弃发生在 Go
	// 侧，与 StRingbufDrop（保留失败）是两个不同的计数，不能混为一谈。
	if got := afterDrop[ebpfplat.StCandidate] - beforeDrop[ebpfplat.StCandidate]; got != dropN {
		t.Fatalf("candidate 增量 = %d, want %d（事件应已进入 ringbuf）", got, dropN)
	}
	if afterDrop[ebpfplat.StRingbufDrop] != beforeDrop[ebpfplat.StRingbufDrop] {
		t.Fatalf("ringbuf_drop 变化了: %d → %d（内核保留不该失败，丢弃在 Go 侧）",
			beforeDrop[ebpfplat.StRingbufDrop], afterDrop[ebpfplat.StRingbufDrop])
	}

	if err := src2.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Close 之后通道保持不关闭：非阻塞读只应看到空（default）或真实事件，
	// 绝不能是 ok=false 的零值包（消费方会把它当成坏包）。
	select {
	case _, ok := <-src2.Packets():
		if !ok {
			t.Fatal("Close 关闭了 Packets() 的通道: 消费方会持续读到零值包")
		}
	default:
	}
	t.Logf("慢消费: %d 个事件全部落在 Go 侧丢弃（Dropped=%d）；内核 candidate +%d、ringbuf_drop 不变；Close 后通道仍未关闭",
		dropN, dropped, dropN)

	// ---- 7) 收尾：不留残留 ----
	if err := be.Detach(h); err != nil {
		t.Fatalf("Detach: %v", err)
	}
	// TCX：Detach 只释放句柄，pin 仍持有内核附着 → 走 Unpin 路径删 pin（--uninstall
	// 的完整回收）；clsact：没有 pin，Detach 即已删掉 filter。
	detachAll(be, ifindex, pinDir)

	if n := countListed(t, be, pinDir, ifindex); n != 0 {
		t.Fatalf("收尾后 List 仍找到 %d 个 knok 附着, want 0", n)
	}
	if n := countKnokFilters(t, ifindex); n != 0 {
		t.Fatalf("收尾后 lo 上仍有 %d 个 knok filter, want 0", n)
	}
	for _, name := range readDirNames(t, pinDir) {
		if strings.HasPrefix(name, "tcx-") {
			t.Fatalf("pin 目录残留附着 pin: %s", name)
		}
	}
	if be.Kind() == "tcx" {
		// 不只是 pin 文件没了：内核里的 link 对象也必须真的释放，否则就是一个
		// 看不见但仍生效的附着（内核释放经 RCU/工作队列，给一段宽限期）。
		waitLinkGone(t, tcxLinkID, 3*time.Second)
		if n := countTCXLinks(t); n != baseLinks {
			t.Fatalf("收尾后 tcx link 数 = %d, want %d", n, baseLinks)
		}
	}
	t.Logf("clean: 无 knok 附着/filter/tcx-* pin（pin 目录剩: %v）", readDirNames(t, pinDir))
}

// sendUDP 往 127.0.0.1:port 发一个 UDP 数据报，每个包用独立 socket。
//
// 写错误不 Fatal：发往无人监听端口的包会招来 ICMP port unreachable，对已 connect
// 的 UDP socket 来说下一次写会以 ECONNREFUSED 失败——但**那个数据报已经发出去了**
// （TC ingress 在 ICMP 之前执行）。所以这里只记录日志。
func sendUDP(t *testing.T, port uint16, payload []byte) {
	t.Helper()
	conn, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
	if err != nil {
		t.Fatalf("dial udp 127.0.0.1:%d: %v", port, err)
	}
	defer conn.Close()
	if _, err := conn.Write(payload); err != nil {
		t.Logf("write udp 127.0.0.1:%d: %v（ICMP unreachable 属预期；数据报已发出）", port, err)
	}
}

// waitEvent 等一个 ringbuf 事件；通道被关闭视为失败（PacketSource 的契约是
// Close 不关闭通道，否则消费方会读到零值包）。
func waitEvent(t *testing.T, src *ebpfplat.RingbufSource, timeout time.Duration) ports.CandidatePacket {
	t.Helper()
	select {
	case pkt, ok := <-src.Packets():
		if !ok {
			t.Fatal("Packets() 的通道被关闭了")
		}
		return pkt
	case <-time.After(timeout):
		t.Fatalf("ringbuf 在 %s 内没有事件", timeout)
		return ports.CandidatePacket{}
	}
}

// readStats 读全部 stats 槽位（失败即 Fatal）。
func readStats(t *testing.T, objs *ebpfplat.KnokObjects) [ebpfplat.StSlots]uint64 {
	t.Helper()
	st, err := ebpfplat.ReadStats(objs)
	if err != nil {
		t.Fatalf("ReadStats: %v", err)
	}
	return st
}

// waitStatAtLeast 轮询到 slot >= want（超时则把整张 stats 表打进失败信息），
// 返回达成时的完整快照。等待是必须的：loopback 包的 TC ingress 在 softirq 里
// 执行，可能在 send 的系统调用返回之后才跑完。
func waitStatAtLeast(t *testing.T, objs *ebpfplat.KnokObjects, slot int, want uint64,
	timeout time.Duration, what string) [ebpfplat.StSlots]uint64 {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		st := readStats(t, objs)
		if st[slot] >= want {
			return st
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: stats[%d] = %d, want >= %d（%s）", what, slot, st[slot], want, statsString(st))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// waitFor 轮询 cond 直到为真（超时即 Fatal）。
func waitFor(t *testing.T, timeout time.Duration, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if cond() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: %s 内未满足", what, timeout)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// statsString 把快照渲染成 "total=1 allow_hit=0 ..."（失败诊断用）。
func statsString(st [ebpfplat.StSlots]uint64) string {
	names := [...]string{"total", "allow_hit", "allow_expired", "candidate", "rate_drop", "ringbuf_drop"}
	var b strings.Builder
	for i, n := range names {
		if i > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%s=%d", n, st[i])
	}
	return b.String()
}

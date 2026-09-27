//go:build linux

package ebpfplat

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	// clsactFilterName 是 knok filter 的名字，也是 clsact 后端对账的唯一锚点
	// （filter 没有 fd 可持有，只能靠名字 + (parent, prio, protocol) 找到它）。
	clsactFilterName = "knok"
	// clsactFilterPref 是 knok filter 的优先级（数值越小越先执行）。固定值让
	// "同一位置替换而非叠加"成立：FilterAdd 带 NLM_F_EXCL，同 (prio, proto,
	// parent) 上的旧 filter 会让新的一次返回 EEXIST。
	clsactFilterPref = 42000
)

// ClsactBackend 是内核 < 6.6 的兜底后端：clsact qdisc 上的 cls_bpf
// direct-action filter。
//
// 它没有 pin：filter 本身就活在内核里、进程退出后仍然生效，所以没有"崩溃
// 存活"这一说（也因此不需要 pin 目录，List 只认内核里的 filter）。
type ClsactBackend struct{}

var (
	_ AttachBackend = (*ClsactBackend)(nil)
	_ Unpinner      = (*ClsactBackend)(nil)
)

func (b *ClsactBackend) Kind() string { return "clsact" }

// Attach 确保 clsact qdisc 存在，然后把 knok 的 cls_bpf filter 放在
// ingress/HANDLE_MIN_INGRESS 上。
func (b *ClsactBackend) Attach(ifindex int, prog *ebpf.Program, pinDir string) (Handle, error) {
	// clsact qdisc 是 ingress/egress filter 的容器。已存在时内核返回 EEXIST，
	// 那是正常情况（第二次 Attach、或别的工具已经建过），忽略即可。
	qdisc := &netlink.Clsact{QdiscAttrs: netlink.QdiscAttrs{
		LinkIndex: ifindex,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}}
	// createdQdisc 记下这个 qdisc 是不是本调用建的：只有自己建的才在失败时
	// 回滚（本来就有的可能是别的实例在用，属共享基础设施）。
	var createdQdisc bool
	if err := netlink.QdiscAdd(qdisc); err != nil {
		if !errors.Is(err, unix.EEXIST) {
			return Handle{}, fmt.Errorf("clsact qdisc ifindex=%d: %w", ifindex, err)
		}
	} else {
		createdQdisc = true
	}

	// 残留对账：同位置的旧 knok filter 必须先删，否则下面的 FilterAdd 会
	// 以 EEXIST 失败（NLM_F_CREATE|NLM_F_EXCL）。这里容忍失败——紧接着的
	// FilterAdd 会把真正的问题（无权限、qdisc 不见了）暴露出来，而在 Detach
	// 路径上同一个函数是严格返回错误的。
	_ = b.removeStale(ifindex)

	f := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: ifindex,
			// 显式 handle：删除时按 handle 精确定位，避免 handle==0 时内核
			// 按 (prio, protocol) 删掉整条 tp 的歧义。
			Handle:   netlink.MakeHandle(0x800, 0),
			Parent:   netlink.HANDLE_MIN_INGRESS,
			Priority: clsactFilterPref,
			// FilterAttrs.Protocol 是主机序（库写入时自己 htons）。
			Protocol: unix.ETH_P_ALL,
		},
		Name:         clsactFilterName,
		Fd:           prog.FD(),
		DirectAction: true,
	}
	if err := netlink.FilterAdd(f); err != nil {
		// 不留半挂状态：qdisc 若是本调用建的，就一并回滚（本来就有的不动）。
		if createdQdisc {
			_ = netlink.QdiscDel(qdisc)
		}
		return Handle{}, fmt.Errorf("cls_bpf add ifindex=%d: %w", ifindex, err)
	}
	return Handle{IfIndex: ifindex, IfName: pinName(ifindex), Kind: b.Kind()}, nil
}

// removeStale 删除该接口 ingress 上所有名为 knok 的 cls_bpf filter（幂等）。
//
// Ruling 4：FilterList 的真实签名是 FilterList(link Link, parent uint32)——
// 不接收 *FilterAttrs，parent 直接传 HANDLE_MIN_INGRESS。
func (b *ClsactBackend) removeStale(ifindex int) error {
	l, err := netlink.LinkByIndex(ifindex)
	if err != nil {
		return fmt.Errorf("link ifindex=%d: %w", ifindex, err)
	}
	filters, err := netlink.FilterList(l, netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		return fmt.Errorf("filter list ifindex=%d: %w", ifindex, err)
	}
	for _, f := range filters {
		bf, ok := f.(*netlink.BpfFilter)
		if !ok || bf.Name != clsactFilterName {
			continue
		}
		if err := netlink.FilterDel(f); err != nil {
			return fmt.Errorf("filter del ifindex=%d handle=%#x: %w", ifindex, bf.Handle, err)
		}
	}
	return nil
}

// Detach 删除 knok 的 cls_bpf filter。
//
// clsact 后端没有 pin，filter 就是附着体：进程退出不会回收它（也就没有
// "崩溃后仍在但没人知道"的问题），所以 Detach 就是完整回收。
func (b *ClsactBackend) Detach(h Handle) error {
	return b.removeStale(h.IfIndex)
}

// Unpin：clsact 没有 pin 可删，--uninstall 的回收动作与 Detach 相同。
func (b *ClsactBackend) Unpin(h Handle, pinDir string) error {
	return b.removeStale(h.IfIndex)
}

// List 枚举所有接口的 ingress filter，返回名为 knok 的那些。
//
// pinDir 不参与：clsact 的附着在且仅在内核里（无 pin），接口名也从 link 里
// 现取，比 TCX 的 pin 文件名更可靠。
func (b *ClsactBackend) List(pinDir string) ([]Handle, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, fmt.Errorf("link list: %w", err)
	}

	var out []Handle
	for _, l := range links {
		filters, err := netlink.FilterList(l, netlink.HANDLE_MIN_INGRESS)
		if err != nil {
			continue // 该接口没有 clsact qdisc / 列举不了：跳过，不影响其它接口
		}
		for _, f := range filters {
			bf, ok := f.(*netlink.BpfFilter)
			if !ok || bf.Name != clsactFilterName {
				continue
			}
			out = append(out, Handle{
				IfIndex: l.Attrs().Index,
				IfName:  l.Attrs().Name,
				Kind:    b.Kind(),
			})
		}
	}
	return out, nil
}

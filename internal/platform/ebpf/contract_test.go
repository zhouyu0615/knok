// C↔Go 契约的**机械**守护。本文件不带构建标签：它只读 bpf/knok_ingress.c 的文本，
// 不加载任何 BPF 对象，因此在 macOS 上（CI、开发机）就能跑——服务器不再是唯一能
// 发现契约漂移的地方。
//
// 背景（final review finding C）：MARK_KNOK、MAX_SPA_PKT、ST_* 与 struct spa_event
// 的字段偏移在 C 与 Go 两侧各写一份，bpf2go 只管程序与 map 的加载，**不管这些
// 常量**。漂移在两个方向都是静默的：
//
//   - mark 漂移 → nftables 的 `meta mark 0x… accept` 匹配不上数据面打的标，
//     每一条已授权流量都被 drop 规则丢掉（"敲门成功但门不开"）；
//   - 偏移漂移 → ringbuf 样本被解析成垃圾，或越过 payload 边界读（丢包、错包）。
//
// types_test.go 只把 Go 侧的数值钉在 Go 侧的字面量上（它无法发现"两侧一起漂"或
// "C 侧单独漂"）。这里补上另一半：直接从 C 源码里**解析**出 define 与字段列表，
// 用 C 的布局规则算出偏移，再与 Go 常量逐项比对。任一侧单独改动，本测试必红。
package ebpfplat

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/zhouyu0615/knok/internal/platform/mark"
)

// cSourcePath 是 C 侧数据面源码相对本包目录（测试的 CWD）的路径。
const cSourcePath = "../../../bpf/knok_ingress.c"

var (
	cDefineRe   = regexp.MustCompile(`(?m)^[ \t]*#define[ \t]+([A-Z0-9_]+)[ \t]+(0[xX][0-9a-fA-F]+|\d+)[ \t]*$`)
	cStructRe   = regexp.MustCompile(`(?s)struct[ \t]+spa_event[ \t]*\{(.*?)\};`)
	cFieldRe    = regexp.MustCompile(`^[ \t]*(__u8|__u16|__u32|__u64)[ \t]+([A-Za-z_][A-Za-z0-9_]*)(?:\[[ \t]*([A-Za-z0-9_]+)[ \t]*\])?[ \t]*;$`)
	cCommentRe  = regexp.MustCompile(`(?s)/\*.*?\*/|//[^\n]*`)
	cIntLiteral = regexp.MustCompile(`^0[xX]`)
)

// cType 是 C 整型的宽度与对齐（本文件只支持 vmlinux.h 风格的基础类型）。
type cType struct{ size, align int }

var cTypes = map[string]cType{
	"__u8":  {1, 1},
	"__u16": {2, 2},
	"__u32": {4, 4},
	"__u64": {8, 8},
}

// cField 是 struct spa_event 的一个字段及其在 C 布局里的偏移。
type cField struct {
	name   string
	offset int
	size   int
}

// parseCDefines 从 C 源码里取出全部 `#define NAME <int>`（十六进制或十进制）。
func parseCDefines(t *testing.T, src string) map[string]uint64 {
	t.Helper()
	out := map[string]uint64{}
	for _, m := range cDefineRe.FindAllStringSubmatch(src, -1) {
		v, err := strconv.ParseUint(m[2], 0, 64)
		if err != nil {
			t.Fatalf("parse #define %s %s: %v", m[1], m[2], err)
		}
		if _, dup := out[m[1]]; dup {
			t.Fatalf("#define %s appears twice; the contract test cannot tell which one is authoritative", m[1])
		}
		out[m[1]] = v
	}
	if len(out) == 0 {
		t.Fatalf("no #define found in %s: the parser or the file layout changed", cSourcePath)
	}
	return out
}

// parseSpaEventLayout 按 C 的布局规则（宽度 + 自然对齐 + 尾部补齐到最大对齐）
// 计算 struct spa_event 每个字段的偏移与结构体总大小。
func parseSpaEventLayout(t *testing.T, src string, defines map[string]uint64) ([]cField, int) {
	t.Helper()
	body := cStructRe.FindStringSubmatch(cCommentRe.ReplaceAllString(src, " "))
	if body == nil {
		t.Fatalf("struct spa_event not found in %s (did the struct get renamed or split?)", cSourcePath)
	}

	var fields []cField
	off, maxAlign := 0, 1
	for _, line := range strings.Split(body[1], "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		m := cFieldRe.FindStringSubmatch(line)
		if m == nil {
			t.Fatalf("unparsed field in struct spa_event: %q (only __uN name / name[size] are supported)", strings.TrimSpace(line))
		}
		typ, name, dim := m[1], m[2], m[3]
		ct := cTypes[typ]
		count := 1
		if dim != "" {
			if n, err := strconv.Atoi(dim); err == nil {
				count = n
			} else {
				n, ok := defines[dim]
				if !ok {
					t.Fatalf("array size %q of %s is neither a number nor a parsed #define", dim, name)
				}
				count = int(n)
			}
		}
		if count <= 0 {
			t.Fatalf("field %s has a non-positive array size %d", name, count)
		}
		off = align(off, ct.align)
		fields = append(fields, cField{name: name, offset: off, size: ct.size * count})
		off += ct.size * count
		if ct.align > maxAlign {
			maxAlign = ct.align
		}
	}
	if len(fields) == 0 {
		t.Fatal("struct spa_event parsed to zero fields")
	}
	return fields, align(off, maxAlign)
}

func align(off, a int) int { return (off + a - 1) / a * a }

// TestContractAgainstCSource 是 finding C 的机械守护：C 源码里解析出来的
// define 与 struct 布局必须与 Go 侧的常量逐项一致，且**数量**也要一致
// （C 新增一个字段/槽位而 Go 没跟上时同样必红）。
func TestContractAgainstCSource(t *testing.T) {
	raw, err := os.ReadFile(cSourcePath)
	if err != nil {
		t.Fatalf("read %s: %v (the contract test must be able to see the C source)", cSourcePath, err)
	}
	src := string(raw)
	defines := parseCDefines(t, src)
	fields, cSize := parseSpaEventLayout(t, src, defines)

	// ---- 1) mark：C 的 #define MARK_KNOK == Go 的 mark.Mark == nft 渲染用的 mark.Hex
	t.Run("MARK_KNOK", func(t *testing.T) {
		cMark, ok := defines["MARK_KNOK"]
		if !ok {
			t.Fatalf("MARK_KNOK not defined in %s", cSourcePath)
		}
		if cMark != uint64(mark.Mark) {
			t.Errorf("MARK_KNOK = %#x (C) vs mark.Mark = %#x (Go): authorized packets would be dropped by nftables",
				cMark, mark.Mark)
		}
		if cMark != uint64(MarkKNOK) {
			t.Errorf("MARK_KNOK = %#x (C) vs MarkKNOK = %#x (Go)", cMark, MarkKNOK)
		}
		if got := fmt.Sprintf("0x%08x", cMark); got != mark.Hex {
			t.Errorf("MARK_KNOK renders as %q but nftables matches %q (mark.Hex)", got, mark.Hex)
		}
	})

	// ---- 2) MAX_SPA_PKT（既决定 payload 缓冲宽度，也决定 ringbuf 保留区大小）
	t.Run("MAX_SPA_PKT", func(t *testing.T) {
		cMax, ok := defines["MAX_SPA_PKT"]
		if !ok {
			t.Fatalf("MAX_SPA_PKT not defined in %s", cSourcePath)
		}
		if cMax != uint64(MaxSPAPkt) {
			t.Errorf("MAX_SPA_PKT = %d (C) vs MaxSPAPkt = %d (Go)", cMax, MaxSPAPkt)
		}
	})

	// ---- 3) stats 槽位：名字与数值都要对上，且集合必须完全一致
	t.Run("ST_* slots", func(t *testing.T) {
		goSlots := []struct {
			cName string
			value int
		}{
			{"ST_TOTAL", StTotal},
			{"ST_ALLOW_HIT", StAllowHit},
			{"ST_ALLOW_EXPIRY", StAllowExpiry},
			{"ST_CANDIDATE", StCandidate},
			{"ST_RATE_DROP", StRateDrop},
			{"ST_RINGBUF_DROP", StRingbufDrop},
			{"ST_SLOTS", StSlots},
		}
		goSet := map[string]bool{}
		for _, s := range goSlots {
			goSet[s.cName] = true
			cv, ok := defines[s.cName]
			if !ok {
				t.Errorf("%s not defined in %s (Go has it, C does not)", s.cName, cSourcePath)
				continue
			}
			if cv != uint64(s.value) {
				t.Errorf("%s = %d (C) vs Go = %d", s.cName, cv, s.value)
			}
		}
		for name := range defines {
			if strings.HasPrefix(name, "ST_") && !goSet[name] {
				t.Errorf("%s is defined in %s but has no Go mirror in types.go", name, cSourcePath)
			}
		}
		if StSlots != len(goSlots)-1 {
			t.Errorf("StSlots = %d, want %d (one past the last slot)", StSlots, len(goSlots)-1)
		}
	})

	// ---- 4) struct spa_event 布局：字段名、顺序、偏移、结构体大小
	t.Run("struct spa_event layout", func(t *testing.T) {
		goOffsets := []struct {
			field string // C 侧字段名
			value int    // Go 侧偏移常量
			name  string // Go 侧常量名（错误信息用）
		}{
			{"ts_ns", EvOffTS, "EvOffTS"},
			{"ifindex", EvOffIfindex, "EvOffIfindex"},
			{"ipver", EvOffIPVer, "EvOffIPVer"},
			{"src_ip", EvOffSrcIP, "EvOffSrcIP"},
			{"src_port", EvOffSrcPort, "EvOffSrcPort"},
			{"dst_port", EvOffDstPort, "EvOffDstPort"},
			{"payload_len", EvOffPLen, "EvOffPLen"},
			{"payload", EvOffPayload, "EvOffPayload"},
		}
		// 显式填充字段（C 的 pad[N]）在 Go 侧没有对应的偏移常量：它不参与解析，
		// 但它的**宽度**会影响后面所有字段的偏移，而那些偏移都被逐项比对——所以
		// pad 写错照样必红。这里只把它从"必须有 Go 镜像"的列表里摘掉。
		var pinned []cField
		for _, f := range fields {
			if isPaddingField(f.name) {
				continue
			}
			pinned = append(pinned, f)
		}
		if len(pinned) != len(goOffsets) {
			t.Fatalf("struct spa_event has %d non-padding fields in C, Go pins %d offsets: %v",
				len(pinned), len(goOffsets), fields)
		}
		for i, want := range goOffsets {
			got := pinned[i]
			if got.name != want.field {
				t.Errorf("field %d: C calls it %q, Go pins %q", i, got.name, want.field)
			}
			if got.offset != want.value {
				t.Errorf("field %s (%s): C offset = %d, Go %s = %d",
					got.name, want.name, got.offset, want.name, want.value)
			}
		}
		if cSize != EvSize {
			t.Errorf("sizeof(struct spa_event) = %d (C), EvSize = %d (Go): ringbuf samples would be misparsed", cSize, EvSize)
		}
		if EvOffPayload+MaxSPAPkt > EvSize {
			t.Errorf("payload ends at %d, beyond EvSize = %d (Go would read out of bounds)", EvOffPayload+MaxSPAPkt, EvSize)
		}
	})
}

// isPaddingField 报告 C 字段名是否是显式填充（pad / pad1 / _pad …）。
func isPaddingField(name string) bool {
	return strings.HasPrefix(strings.TrimLeft(name, "_"), "pad")
}

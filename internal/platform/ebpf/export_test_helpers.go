//go:build linux && integration

// 本文件只在 integration 构建里存在：它把包内未导出的实现细节导出给外部
// 测试包（package ebpfplat_test）使用，形式与标准库的 export_test.go 一致。
//
// MustLoadForTest 由 Task 6 引入（本任务的集成测试是它的第一个消费者）：
// Task 7 的 maps.go 落地后 LoadObjects 会取代这里的加载逻辑，届时保持签名
// 不变、改为复用即可。

package ebpfplat

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// bpfFSPath 是 bpf 文件系统的挂载点。
//
// pin 只能落在这里：cilium 的 Link.Pin / Map.Pin 都会检查目标目录的 fstype
// （internal/sys/pinning.go 要求 BPF_FS_MAGIC），/tmp 之类的临时目录必然失败。
const bpfFSPath = "/sys/fs/bpf"

// TestPinDir 返回本次测试专属的 pin 目录（bpffs 下，按测试名隔离），并登记
// 测试结束后的清理（删掉整个目录，连同里面的 map pin 与 tcx-* link pin）。
//
// 目录名对测试名做净化（子测试名里会有 '/'）。生产侧（Task 9）用的是配置传入
// 的一个 pinDir，map pin 与 tcx-* link pin 同样共处其中——这里刻意保持一致。
func TestPinDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(bpfFSPath, "knok-it-"+sanitizeName(t.Name()))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("需要可写的 bpffs（%s）: %v", bpfFSPath, err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// MustLoadForTest 在测试专属的 pin 目录里加载 knok 的程序与四张 map，并在测试
// 结束时关闭对象、清掉 pin 目录。
//
// 它刻意直接调用 bpf2go 生成的 loadKnokObjects，而不是 Task 7 才会有的
// LoadObjects（避免本任务依赖未来的文件）。
//
// 生成物里的四张 map 都带 LIBBPF_PIN_BY_NAME（bpf/knok_ingress.c），所以
// PinPath 必须是 bpffs 下的真实目录；加载前先清掉上一轮失败运行的 pin，
// 保证用例可重复执行，且不会复用上一轮残留的 map。
func MustLoadForTest(t *testing.T) *knokObjects {
	t.Helper()

	pinDir := TestPinDir(t)
	if err := clearPinDir(pinDir); err != nil {
		t.Fatalf("清理 pin 目录 %s: %v", pinDir, err)
	}

	// 无 memcg 记账的老内核（< 5.11）加载 BPF 对象需要放宽 RLIMIT_MEMLOCK。
	// 6.8 上不需要，失败也不致命，best-effort 即可。
	_ = rlimit.RemoveMemlock()

	objs := &knokObjects{}
	if err := loadKnokObjects(objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: pinDir},
	}); err != nil {
		t.Fatalf("load knok objects: %v", err)
	}
	t.Cleanup(func() {
		_ = objs.Close()
		_ = os.RemoveAll(pinDir)
	})
	return objs
}

// TCXPinPathForTest 暴露 pin 路径规则，供外部集成测试断言 pin 的存在/消失，
// 避免测试里重复一遍文件名格式。
func TCXPinPathForTest(pinDir string, ifindex int) string {
	return tcxPinPath(pinDir, ifindex)
}

// KnokFilterNameForTest 暴露 cls_bpf filter 名（clsact 后端对账用的锚点），
// 供外部集成测试独立地数内核里的 knok filter。
const KnokFilterNameForTest = clsactFilterName

// clearPinDir 删掉目录里的所有条目（保留目录本身）：吸收上一轮的 pin 残留。
func clearPinDir(dir string) error {
	ents, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return os.MkdirAll(dir, 0o755)
		}
		return err
	}
	for _, e := range ents {
		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

// sanitizeName 把测试名变成安全的目录名片段。
func sanitizeName(name string) string {
	out := make([]rune, 0, len(name))
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			out = append(out, r)
		default:
			out = append(out, '_')
		}
	}
	return string(out)
}

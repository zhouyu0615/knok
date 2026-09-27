//go:build linux

package ebpfplat

import (
	"encoding/binary"
	"fmt"
	"os"
	"unsafe"

	"github.com/cilium/ebpf"
)

// DefaultPinDir 是 knokd 的默认 pin 目录（spec §5.1 冻结：/sys/fs/bpf/knok）。
const DefaultPinDir = "/sys/fs/bpf/knok"

// cfgValSize 是 C 侧 struct cfg_val 的字节数：
//
//	struct cfg_val { __u32 spa_port; __u32 min_len; __u32 max_len; };
//
// WriteCfg 用 unsafe.Pointer 直接写字节（值布局是两侧共享的 ABI），长度写错
// 不会报错、只会把 cfg 写坏，所以这里把它固化成常量并在写入前自检。
const cfgValSize = 12

// KnokObjects 是 bpf2go 生成对象的导出别名（Ruling 8）。
//
// knokObjects 由生成代码定义且未导出，而 Task 9 的 metrics handler 需要把加载好的
// 对象交给 ReadStats——别名让调用方不必触碰生成文件（"生成物不许手改"的边界保持
// 清晰）。别名就是同一类型，可直接互换使用。
type KnokObjects = knokObjects

// LoadObjects 加载 knok 的 BPF 集合（一个程序 + 四张 map）。
//
// 四张 map 在 C 侧都带 LIBBPF_PIN_BY_NAME，配合这里的 PinPath：pin 目录里已存在的
// 同名 map 会被**复用**而不是新建——这是"knokd 重启后已授权流量不中断"的一半
// （另一半是 TCX link 的 pin，见 backend_tcx.go）。因此 pinDir 必须是 bpffs 下的
// 目录：cilium 的 pin 路径会检查目标目录的 fstype，普通文件系统上会显式失败。
//
// 调用方负责 Close 返回的对象。
func LoadObjects(pinDir string) (*knokObjects, error) {
	if err := os.MkdirAll(pinDir, 0o755); err != nil {
		return nil, fmt.Errorf("pin dir %s: %w", pinDir, err)
	}

	objs := &knokObjects{}
	if err := loadKnokObjects(objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: pinDir},
	}); err != nil {
		return nil, fmt.Errorf("load bpf objects: %w", err)
	}
	return objs, nil
}

// WriteCfg 把运行参数写进 cfg map（ARRAY，只有 index 0 一个槽位）。
//
// 三个值都被 C 侧按**有限宽度**使用，越界会静默劣化而不是报错，所以这里一律
// 拒绝，绝不静默截断（判据见 validateCfg）。写入用 UpdateAny（幂等）：重复调用
// 只是覆盖同一个槽位，这也让 knokd 重启后重写 cfg 是安全的。
func WriteCfg(objs *knokObjects, spaPort, minLen, maxLen uint32) error {
	if err := validateCfg(spaPort, minLen, maxLen); err != nil {
		return err
	}

	val := make([]byte, cfgValSize)
	binary.NativeEndian.PutUint32(val[0:], spaPort)
	binary.NativeEndian.PutUint32(val[4:], minLen)
	binary.NativeEndian.PutUint32(val[8:], maxLen)

	key := uint32(0)
	if err := objs.Cfg.Update(unsafe.Pointer(&key), unsafe.Pointer(&val[0]), ebpf.UpdateAny); err != nil {
		return fmt.Errorf("write cfg: %w", err)
	}
	return nil
}

// validateCfg 校验 WriteCfg 的三个入参。每条都对应一个**静默**失败模式：
//
//   - spa_port 被 C 侧与 key.port（u16）比较：0 或 >65535 永远匹配不上，
//     表现为"SPA 端口收不到任何候选包"；
//   - max_len 以上的载荷会被 C 侧按 MAX_SPA_PKT 截断（copy_len 的上限）：
//     声明超过 MaxSPAPkt 的 max_len 会让"通过校验的包"与"被完整上送的包"
//     长度不一致，PSK 载荷被截断后验签必然失败；
//   - min_len > max_len 没有任何包能通过，同样是静默无候选。
//
// 单独成函数是为了能不经 map（不需要 root）直接单测——它是 WriteCfg 唯一可能
// 拒绝输入的路径，值得钉住。
func validateCfg(spaPort, minLen, maxLen uint32) error {
	if spaPort == 0 || spaPort > 65535 {
		return fmt.Errorf("spa_port %d out of range (want 1..65535): the dataplane compares it as u16", spaPort)
	}
	if maxLen > MaxSPAPkt {
		return fmt.Errorf("max_len %d exceeds MaxSPAPkt %d: payloads above it are silently truncated", maxLen, MaxSPAPkt)
	}
	if minLen > maxLen {
		return fmt.Errorf("min_len %d > max_len %d: no packet can ever match", minLen, maxLen)
	}
	return nil
}

// ReadStats 读取全部 stats 槽位（ARRAY，索引即 St* 常量）。
//
// 返回的数组按索引对应 StTotal…StRingbufDrop；出错时返回已读到的部分（调用方
// 一般直接当失败处理）。ARRAY map 的槽位在加载时零初始化，所以"全 0"是干净的
// 基线——集成测试用它取增量。
func ReadStats(objs *knokObjects) ([StSlots]uint64, error) {
	var out [StSlots]uint64
	for i := uint32(0); i < StSlots; i++ {
		var v uint64
		key := i
		if err := objs.Stats.Lookup(unsafe.Pointer(&key), unsafe.Pointer(&v)); err != nil {
			return out, fmt.Errorf("read stats slot %d: %w", i, err)
		}
		out[i] = v
	}
	return out, nil
}

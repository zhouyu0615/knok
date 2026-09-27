package main

import (
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// configError 标记"用户可修"的失败（配置解析/校验/接口不存在）。main 用它把退出码
// 分成 2（改配置）与 3（换内核/提权）；errors.As 穿透 fmt.Errorf 的包装，所以 run()
// 内部怎么包都行。
//
// 它与本文件其余部分一样不带构建标签：配置层的概念不依赖平台，而放在这里也让
// 与配置无关的判定（startup_gate.go 的信号闸门）能在任何平台上断言"这不是配置错"。
type configError struct{ err error }

func (e *configError) Error() string { return e.err.Error() }
func (e *configError) Unwrap() error { return e.err }

// Config 是 /etc/knok/knokd.toml 的映射。
//
// 契约：**配置文件是唯一的配置来源**。CLI 只有 -config / -uninstall / -metrics
// 三个开关，绝不提供能覆盖这里任何字段的 flag——否则"机器上跑的到底是什么策略"
// 就不再能从磁盘上那份文件读出，审计与排障都会失真（spec §6）。
//
// 字段名与 TOML 键一一对应（显式 toml tag，不依赖库的默认小写化规则）。
type Config struct {
	Listen struct {
		SPAUDPPort     uint16   `toml:"spa_udp_port"`
		ProtectedPorts []uint16 `toml:"protected_ports"`
	} `toml:"listen"`
	Keys struct {
		PSK string `toml:"psk"` // "hex:<64hex>" —— M2 临时
	} `toml:"keys"`
	Policy struct {
		AllowedPorts []uint16 `toml:"allowed_ports"`
		MaxTTL       string   `toml:"max_ttl"`
		TSWindow     string   `toml:"ts_window"`
	} `toml:"policy"`
	Safety struct {
		AdminAllow []string `toml:"admin_allow"` // CIDR 列表，M2 支持 /32、/128
	} `toml:"safety"`
	Interfaces struct {
		Mode     string   `toml:"mode"` // M2 仅 "explicit"
		Explicit []string `toml:"explicit"`
	} `toml:"interfaces"`
	Pin struct {
		Dir string `toml:"dir"`
	} `toml:"pin"`
}

// LoadConfig 读取并做**结构性**校验，只填默认值，不做任何内核操作。
//
// 它只负责"这份配置在语法与自洽性上是否可用"：解析失败、interfaces 模式非法、
// 时长字符串非法都在这里失败。语义校验（密钥格式、地址前缀、接口是否存在）由
// PSK/Durations/AdminAddrs/ResolveInterfaces 各自负责，run() 把它们全部排在
// step [1]——任何一步失败都发生在加载 maps/attach 之前，这正是"配置错不动内核
// 状态"的实现方式。
//
// 默认值只填空键（空字符串/零值），永远不覆盖用户写下的值。
func LoadConfig(path string) (*Config, error) {
	var c Config
	if _, err := toml.DecodeFile(path, &c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if c.Listen.SPAUDPPort == 0 {
		c.Listen.SPAUDPPort = 4242
	}
	if c.Pin.Dir == "" {
		c.Pin.Dir = defaultPinDir
	}
	if !validPinDir(c.Pin.Dir) {
		return nil, fmt.Errorf("config: pin.dir %q is not a safe cleanup target: it must be an absolute path with at least two elements (e.g. /sys/fs/bpf/knok) because -uninstall recursively deletes it as root", c.Pin.Dir)
	}
	if c.Interfaces.Mode != "explicit" || len(c.Interfaces.Explicit) == 0 {
		return nil, fmt.Errorf("config: M2 requires interfaces.mode=explicit with at least one interface")
	}
	if c.Policy.MaxTTL == "" {
		c.Policy.MaxTTL = "30m"
	}
	if c.Policy.TSWindow == "" {
		c.Policy.TSWindow = "300s"
	}
	// "能解析但 <= 0"的时长在这里就拒绝：TTL 为 0 的包能穿过管线（只有 msg.TTL
	// 为 0 才被拒），而 cap 到 max_ttl=0 后授权立刻过期——审计里却是一条授权成功。
	// 语法错误的时长**不**在这里报：那是 Durations 的职责（run 的 step [1]），
	// 错误文案与位置都已固定。两条路径的终点一致（配置错 → 退出码 2）。
	if err := requirePositiveDuration("policy.max_ttl", c.Policy.MaxTTL); err != nil {
		return nil, err
	}
	if err := requirePositiveDuration("policy.ts_window", c.Policy.TSWindow); err != nil {
		return nil, err
	}
	return &c, nil
}

// validPinDir 报告一个路径能否作为 -uninstall 的 os.RemoveAll 目标。
//
// 这条路径上的错误是**不可逆**的：-uninstall 以 root 递归删除该目录，一个形如
// /sys/fs/bpf 的笔误（少写 /knok）会把别的工具 pin 的 map/程序全部删掉，然后
// 报告成功。所以判据收紧到"看起来像 <root>/<leaf>"：
//
// defaultPinDir 是 pin 目录的默认值（spec §5.1 冻结：/sys/fs/bpf/knok），也是
// validPinDir 判定"祖先"的基准。它与 ebpfplat.DefaultPinDir（Linux 专属包）同值，
// 这里单独写一份是为了让本文件不带构建标签——判据本身必须能在 macOS 上单测。
const defaultPinDir = "/sys/fs/bpf/knok"

//   - 必须是绝对路径（相对路径的删除目标取决于进程 CWD，无法审计）；
//   - 原始路径里不得出现 . 或 .. 分量：Clean 会把它们解析掉，于是"看起来在 A、
//     实际删 B"（/sys/fs/bpf/.. 的 Clean 结果是 /sys/fs——正是不可逆的多删一层）；
//   - Clean 后不能是 /、.、..，且至少有**两个**非空分量（/sys、/etc 这类根拒绝）；
//   - 不得是默认 pin 目录的**祖先**：少了最后一级的 /sys/fs/bpf 有足够的分量数，
//     但删它就是把所有其它工具 pin 的 map/程序一起删掉（finding A 的原始场景）。
//
// 合法的值：/sys/fs/bpf/knok、/sys/fs/bpf/knok-e2e（后者是 e2e 的隔离目录）。
//
// 本函数不带构建标签（配置层的判定与平台无关），因此 LoadConfig 与 main.go 的
// 删除点共用同一份判据，并且能在 macOS 上单测。
func validPinDir(dir string) bool {
	if dir == "" || !filepath.IsAbs(dir) {
		return false
	}
	for _, part := range strings.Split(dir, "/") {
		if part == "." || part == ".." {
			return false
		}
	}
	clean := filepath.Clean(dir)
	if clean == "/" || clean == "." || clean == ".." {
		return false
	}
	if strings.HasPrefix(defaultPinDir, clean+"/") {
		return false // clean 是默认 pin 目录的祖先
	}
	parts := strings.Split(strings.Trim(clean, "/"), "/")
	return len(parts) >= 2
}

// requirePositiveDuration 挡住"能解析但 <= 0"的时长；解析失败的值返回 nil
// （交给 Durations 报错，见 LoadConfig 的注释）。
func requirePositiveDuration(name, v string) error {
	d, err := time.ParseDuration(v)
	if err != nil {
		return nil
	}
	if d <= 0 {
		return fmt.Errorf("config: %s = %q must be > 0 (a zero duration yields a grant that expires immediately)", name, v)
	}
	return nil
}

// policyWarnings 返回"配置能启动、但会让某个受保护端口永久锁死"的组合说明。
//
// 两条都是静默的远程锁死：
//
//   - protected_ports 里有 allowed_ports 之外的端口：drop 规则照装，但没有任何
//     客户端能被授予它（管线要求请求端口 ⊆ allowed_ports），该端口从此永久
//     drop——包括管理员自己；
//   - allowed_ports 为空：任何敲门都只会得到 reject_reason=policy。
//
// 是**警告而不是错误**：合法的运维形态存在（例如先用 safety.admin_allow 打开
// 再补 allowed_ports），拒绝启动会把一份可用的配置判死。但它必须在装 drop 规则
// **之前**说出来——装完之后这个组合就是"门锁上了、钥匙没了"。
func policyWarnings(c *Config) []string {
	var out []string
	if len(c.Policy.AllowedPorts) == 0 {
		out = append(out, "policy.allowed_ports is empty: every knock is rejected with reject_reason=policy; only safety.admin_allow can open a protected port")
	}
	for _, p := range c.Listen.ProtectedPorts {
		if !slices.Contains(c.Policy.AllowedPorts, p) {
			out = append(out, fmt.Sprintf("listen.protected_ports includes %d but policy.allowed_ports does not: the drop rule is installed for %d while no client can ever be granted it (silent remote lockout)", p, p))
		}
	}
	return out
}

// PSK 解析 M2 的预共享密钥。
//
// 格式 `hex:<64 hex chars>` 必须与 cmd/knok 的 --psk 完全一致（同一个字符串，
// 同一份密钥材料）：两侧用不同的解析规则会得到"客户端敲了门、服务端算出的密钥
// 不同"的静默失败——包结构合法、AEAD 校验失败，只有 audit 里能看到 auth_failed。
// 因此这里严格到连前缀大小写都不宽松：任何偏差都当配置错误报出来。
func (c *Config) PSK() ([32]byte, error) {
	var k [32]byte
	s, ok := strings.CutPrefix(c.Keys.PSK, "hex:")
	if !ok {
		return k, fmt.Errorf("keys.psk must be hex:<64 hex chars>")
	}
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return k, fmt.Errorf("keys.psk invalid: %v", err)
	}
	copy(k[:], b)
	return k, nil
}

// Durations 把策略时长解析成 time.Duration。错误里带上原始字符串（谁写的就报谁）。
func (c *Config) Durations() (maxTTL, tsWindow time.Duration, err error) {
	if maxTTL, err = time.ParseDuration(c.Policy.MaxTTL); err != nil {
		return
	}
	tsWindow, err = time.ParseDuration(c.Policy.TSWindow)
	return
}

// AdminAddrs 解析逃生通道的地址列表。
//
// 两条约束都是刻意的：
//
//   - 必须是 CIDR 形式（ParsePrefix）：裸地址 "10.0.0.1" 被拒绝，避免"看着是
//     地址、实际被解析成别的对象"的歧义；写 /32 或 /128 是显式的。
//   - 前缀长度必须等于地址位宽（单地址）。M2 的实现是逐地址 GrantForever，没有
//     "整个网段永久放行"的语义；若允许 /8，只有网络地址会被放行——真实管理机的
//     地址不在其中。表现是"逃生通道填了却打不开门"，而这恰恰是最需要它可用的
//     那一次。所以宁可拒绝配置，也不静默按网络地址放行。
func (c *Config) AdminAddrs() ([]netip.Addr, error) {
	var out []netip.Addr
	for _, s := range c.Safety.AdminAllow {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("safety.admin_allow %q: %w", s, err)
		}
		if p.Bits() != p.Addr().BitLen() {
			return nil, fmt.Errorf("safety.admin_allow %q: M2 only supports single-address prefixes (/32, /128)", s)
		}
		out = append(out, p.Addr())
	}
	return out, nil
}

// uninstallPinDir 解析 -uninstall 该清理哪个 pin 目录。
//
// 回收路径刻意**不依赖配置可用**：配置被删掉、或写坏到起不来，恰恰是最需要把
// 防火墙拆掉的时刻（否则只能手敲 nft delete table inet knok）。因此这里只做一次
// **纯解析**（toml.DecodeFile 到一个只含 pin.dir 的临时结构），不跑 LoadConfig 的
// 语义校验：PSK 格式、时长、接口模式都可能是坏配置，而它们与"该删哪个目录"无关。
//
// 唯一必须违逆"不挡住回收"原则的字段就是 pin.dir 本身——它是紧接着 os.RemoveAll
// 的目标。读得出来但过不了 validPinDir 时返回错误，调用方据此**拒绝删除**（而不是
// 退回默认目录）：一份指向 /sys/fs/bpf 的笔误配置绝不能被当成"清理
// /sys/fs/bpf/knok"的许可，也不能让删除目标变成"配置说 A、实际删 B"。
//
// fallback 由调用方传入而不是在这里直接引用 ebpfplat.DefaultPinDir：本文件不带
// 构建标签（判定与平台无关、可在 macOS 上单测），而 ebpfplat 是 Linux 专属包。
//
// 读得出来且安全时用配置里的 pin.dir：pin 文件（tcx-<ifindex>）是唯一无法从内核
// 可见状态反推位置的东西，能用配置定位就精确用它。
func uninstallPinDir(cfgPath, fallback string) (string, error) {
	var fc struct {
		Pin struct {
			Dir string `toml:"dir"`
		} `toml:"pin"`
	}
	if _, err := toml.DecodeFile(cfgPath, &fc); err != nil {
		slog.Warn("uninstall: config unreadable, cleaning the default pin dir only; pass a valid -config to clean a custom pin.dir",
			"config", cfgPath, "pin_dir", fallback, "err", err)
		return fallback, nil
	}
	if fc.Pin.Dir == "" {
		return fallback, nil // 没写 pin.dir：LoadConfig 也会用这个默认值
	}
	if !validPinDir(fc.Pin.Dir) {
		return "", fmt.Errorf("config %s: pin.dir %q is not a safe cleanup target (want an absolute path with at least two elements, e.g. %s)", cfgPath, fc.Pin.Dir, fallback)
	}
	return fc.Pin.Dir, nil
}

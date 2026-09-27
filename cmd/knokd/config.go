package main

import (
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/netip"
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
		c.Pin.Dir = "/sys/fs/bpf/knok"
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
	return &c, nil
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
// 防火墙拆掉的时刻（否则只能手敲 nft delete table inet knok）。防火墙表与 tc/
// clsact 附着都不需要配置就能回收，所以配置读不出来时这里只退化为 fallback
// （ebpfplat.DefaultPinDir）并记一条 warn，绝不中止。
//
// fallback 由调用方传入而不是在这里直接引用 ebpfplat.DefaultPinDir：本文件不带
// 构建标签（判定与平台无关、可在 macOS 上单测），而 ebpfplat 是 Linux 专属包。
//
// 读得出来时用配置里的 pin.dir：pin 文件（tcx-<ifindex>）是唯一无法从内核可见
// 状态反推位置的东西，能用配置定位就精确用它。
func uninstallPinDir(cfgPath, fallback string) string {
	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		slog.Warn("uninstall: config unreadable, cleaning the default pin dir only; pass a valid -config to clean a custom pin.dir",
			"config", cfgPath, "pin_dir", fallback, "err", err)
		return fallback
	}
	return cfg.Pin.Dir
}

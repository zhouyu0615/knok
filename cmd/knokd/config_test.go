package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zhouyu0615/knok/pkg/protocol"
)

// validPSKHex 与 cmd/knok/main_test.go 用的是同一个夹具字符串，不是巧合：
// 两侧共用一份夹具，任何一侧改了 hex: 的格式约定，另一侧就会红。
const validPSKHex = "0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9"

// minCfg 是能通过全部校验的最小配置（只有无法给默认值的字段）。
const minCfg = `[keys]
psk = "hex:` + validPSKHex + `"

[interfaces]
mode = "explicit"
explicit = ["lo"]
`

// writeCfg 落盘一份配置到临时目录并返回路径。
func writeCfg(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "knokd.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// TestLoadConfigDefaults 钉住 spec §5.1/§6 里承诺的默认值。它们同时是"配置
// 可以很小"的保证：漏写这些键不是错误，而是取文档里的默认值。
func TestLoadConfigDefaults(t *testing.T) {
	cfg, err := LoadConfig(writeCfg(t, minCfg))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Listen.SPAUDPPort != 4242 {
		t.Errorf("spa_udp_port default = %d, want 4242", cfg.Listen.SPAUDPPort)
	}
	if cfg.Pin.Dir != "/sys/fs/bpf/knok" {
		t.Errorf("pin.dir default = %q, want /sys/fs/bpf/knok", cfg.Pin.Dir)
	}
	if cfg.Policy.MaxTTL != "30m" {
		t.Errorf("max_ttl default = %q, want 30m", cfg.Policy.MaxTTL)
	}
	if cfg.Policy.TSWindow != "300s" {
		t.Errorf("ts_window default = %q, want 300s", cfg.Policy.TSWindow)
	}
	maxTTL, tsWindow, err := cfg.Durations()
	if err != nil {
		t.Fatalf("Durations: %v", err)
	}
	if maxTTL != 30*time.Minute {
		t.Errorf("max_ttl parsed = %s, want 30m", maxTTL)
	}
	if tsWindow != 300*time.Second {
		t.Errorf("ts_window parsed = %s, want 300s", tsWindow)
	}
}

// TestLoadConfigExplicitValues 覆盖显式取值不被默认值覆盖（默认值只能填空，
// 不能改写用户写下的值）。
func TestLoadConfigExplicitValues(t *testing.T) {
	cfg, err := LoadConfig(writeCfg(t, `[listen]
spa_udp_port = 1234
protected_ports = [22222]

[keys]
psk = "hex:`+validPSKHex+`"

[policy]
allowed_ports = [22222]
max_ttl = "5m"
ts_window = "60s"

[interfaces]
mode = "explicit"
explicit = ["lo", "eth0"]

[pin]
dir = "/sys/fs/bpf/knok-e2e"
`))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Listen.SPAUDPPort != 1234 {
		t.Errorf("spa_udp_port = %d, want 1234 (显式值被默认值覆盖了)", cfg.Listen.SPAUDPPort)
	}
	if len(cfg.Listen.ProtectedPorts) != 1 || cfg.Listen.ProtectedPorts[0] != 22222 {
		t.Errorf("protected_ports = %v, want [22222]", cfg.Listen.ProtectedPorts)
	}
	if len(cfg.Policy.AllowedPorts) != 1 || cfg.Policy.AllowedPorts[0] != 22222 {
		t.Errorf("allowed_ports = %v, want [22222]", cfg.Policy.AllowedPorts)
	}
	if cfg.Pin.Dir != "/sys/fs/bpf/knok-e2e" {
		t.Errorf("pin.dir = %q, want /sys/fs/bpf/knok-e2e", cfg.Pin.Dir)
	}
	maxTTL, tsWindow, err := cfg.Durations()
	if err != nil {
		t.Fatalf("Durations: %v", err)
	}
	if maxTTL != 5*time.Minute || tsWindow != time.Minute {
		t.Errorf("durations = (%s, %s), want (5m0s, 1m0s)", maxTTL, tsWindow)
	}
}

// TestLoadConfigRejectsBadInput 覆盖"配置错必须在校验期就失败"的全部形状。
// 每条都在 step [1]，即任何内核状态被触碰之前——这是启动顺序不变量的第一道闸。
func TestLoadConfigRejectsBadInput(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string // 错误里必须出现的关键词
	}{
		{
			name: "malformed toml",
			body: "[keys\npsk = 1\n",
			want: "config:",
		},
		{
			name: "mode missing",
			body: "[keys]\npsk = \"hex:" + validPSKHex + "\"\n",
			want: "interfaces.mode=explicit",
		},
		{
			name: "mode auto",
			body: "[keys]\npsk = \"hex:" + validPSKHex + "\"\n[interfaces]\nmode = \"auto\"\nexplicit = [\"lo\"]\n",
			want: "interfaces.mode=explicit",
		},
		{
			name: "mode exclude",
			body: "[keys]\npsk = \"hex:" + validPSKHex + "\"\n[interfaces]\nmode = \"exclude\"\nexclude = [\"lo\"]\n",
			want: "interfaces.mode=explicit",
		},
		{
			name: "explicit empty",
			body: "[keys]\npsk = \"hex:" + validPSKHex + "\"\n[interfaces]\nmode = \"explicit\"\nexplicit = []\n",
			want: "at least one interface",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadConfig(writeCfg(t, tc.body))
			if err == nil {
				t.Fatalf("LoadConfig accepted invalid config (%s)", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// TestDurationsRejectsBadUnit 单独钉住 Durations 的错误路径。注意时长**不是**
// 结构校验的一部分：LoadConfig 只负责填空默认值，非法时长在 run() 的 step [1]
// 由 Durations 报出（仍是配置错 → 退出码 2，且发生在任何内核操作之前）。
func TestDurationsRejectsBadUnit(t *testing.T) {
	tests := []struct{ name, policy string }{
		{name: "max_ttl", policy: "[policy]\nmax_ttl = \"5minutes\"\n"},
		{name: "ts_window", policy: "[policy]\nts_window = \"forever\"\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := LoadConfig(writeCfg(t, minCfg+tc.policy))
			if err != nil {
				t.Fatalf("LoadConfig: %v", err)
			}
			if _, _, err := cfg.Durations(); err == nil {
				t.Fatalf("Durations accepted %s", tc.policy)
			}
		})
	}
}

// TestPSKFormat 钉住 keys.psk 只接受 `hex:<64 hex chars>`——与否决任何宽松形式
// （裸 hex、大写前缀、短/长 key）。宽松解析是危险的：一个被截断的 key 会静默地
// 让服务端与客户端各持不同密钥，表现为"敲门永远失败"而不是配置报错。
func TestPSKFormat(t *testing.T) {
	pskBody := func(psk string) string {
		return fmt.Sprintf("[keys]\npsk = %q\n[interfaces]\nmode = \"explicit\"\nexplicit = [\"lo\"]\n", psk)
	}

	tests := []struct {
		name    string
		psk     string
		wantErr bool
	}{
		{name: "canonical", psk: "hex:" + validPSKHex},
		{name: "no prefix", psk: validPSKHex, wantErr: true},
		{name: "uppercase prefix", psk: "HEX:" + validPSKHex, wantErr: true},
		{name: "empty", psk: "", wantErr: true},
		{name: "prefix only", psk: "hex:", wantErr: true},
		{name: "too short", psk: "hex:" + validPSKHex[:62], wantErr: true},
		{name: "too long", psk: "hex:" + validPSKHex + "00", wantErr: true},
		{name: "non hex", psk: "hex:" + strings.Repeat("zz", 32), wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := LoadConfig(writeCfg(t, pskBody(tc.psk)))
			if err != nil {
				t.Fatalf("LoadConfig: %v", err)
			}
			got, err := cfg.PSK()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("PSK() accepted %q", tc.psk)
				}
				return
			}
			if err != nil {
				t.Fatalf("PSK(): %v", err)
			}
			want := decodeHex(t, validPSKHex)
			if got != want {
				t.Errorf("PSK() = %x, want %x", got, want)
			}
		})
	}
}

// TestPSKRoundTripWithClient 是 Task 10 复查留下的那笔账：客户端与守护进程必须
// 对同一个字符串得出同一个密钥。
//
// 不变量：`knok keygen --psk` 打印的字符串（hex:<64>，见 cmd/knok 的
// hex.EncodeToString）粘进 knokd.toml 的 keys.psk 后，客户端用该密钥加密的包
// 必须能被守护进程配置里解析出的密钥解开。若两侧对前缀/长度的约定漂移，本测试
// 失败而不是部署后才暴露。
func TestPSKRoundTripWithClient(t *testing.T) {
	var raw [32]byte
	for i := range raw {
		raw[i] = byte(i + 1)
	}
	keygenOut := "hex:" + hex.EncodeToString(raw[:]) // 与 cmd/knok cmdKeygen 的输出形状一致

	cfg, err := LoadConfig(writeCfg(t, fmt.Sprintf(
		"[keys]\npsk = %q\n[interfaces]\nmode = \"explicit\"\nexplicit = [\"lo\"]\n", keygenOut)))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	server, err := cfg.PSK()
	if err != nil {
		t.Fatalf("daemon PSK(): %v", err)
	}
	client, err := clientPSK(keygenOut)
	if err != nil {
		t.Fatalf("client parse: %v", err)
	}
	if server != client {
		t.Fatalf("key material diverged: daemon %x client %x", server, client)
	}

	msg := protocol.Message{
		TS:    1700000000,
		Nonce: [16]byte{9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 1, 2, 3, 4, 5, 6},
		Ports: []uint16{22222},
		TTL:   60,
	}
	pkt, err := protocol.EncodePSK(msg, client)
	if err != nil {
		t.Fatalf("EncodePSK: %v", err)
	}
	got, err := protocol.DecodePSK(pkt, server)
	if err != nil {
		t.Fatalf("daemon could not decode the client's packet: %v", err)
	}
	if got.TS != msg.TS || got.Nonce != msg.Nonce || got.TTL != msg.TTL ||
		len(got.Ports) != 1 || got.Ports[0] != 22222 {
		t.Errorf("decoded %+v, want %+v", got, msg)
	}
}

// clientPSK 是 cmd/knok 的 parsePSK 的**镜像**（未导出，跨 main 包无法引用；
// 其行为由 cmd/knok/main_test.go 钉住）。这里刻意重复一遍：这个测试要验证的正是
// "客户端产出的字符串 → 服务端接受"的一致性，复用实现反而会让漂移两边一起变。
func clientPSK(s string) ([32]byte, error) {
	var k [32]byte
	body, ok := strings.CutPrefix(s, "hex:")
	if !ok {
		return k, fmt.Errorf("--psk must be hex:<64 hex chars>")
	}
	b, err := hex.DecodeString(body)
	if err != nil || len(b) != 32 {
		return k, fmt.Errorf("--psk invalid")
	}
	copy(k[:], b)
	return k, nil
}

// TestAdminAddrs 钉住 safety.admin_allow 的两个语义：
//
//   - 只在 ParsePrefix 成功时接受 → 配置必须写 CIDR 形式（"10.0.0.1" 这种裸地址
//     被拒绝），不会出现"看着像地址、实际解析成了别的东西"；
//   - 只接受单地址前缀（/32、/128）。M2 的逃生通道是逐地址的 GrantForever，
//     把 /8 当成"整个网段放行"会静默放行上千个地址——这是本任务最危险的
//     静默失败模式，因此在这里拒绝而不是静默取网络地址。
func TestAdminAddrs(t *testing.T) {
	cfgWith := func(addrs string) *Config {
		t.Helper()
		cfg, err := LoadConfig(writeCfg(t, minCfg+"[safety]\nadmin_allow = ["+addrs+"]\n"))
		if err != nil {
			t.Fatalf("LoadConfig: %v", err)
		}
		return cfg
	}

	t.Run("single addresses accepted", func(t *testing.T) {
		cfg := cfgWith(`"203.0.113.7/32", "2001:db8::1/128"`)
		got, err := cfg.AdminAddrs()
		if err != nil {
			t.Fatalf("AdminAddrs: %v", err)
		}
		want := []string{"203.0.113.7", "2001:db8::1"}
		if len(got) != len(want) {
			t.Fatalf("AdminAddrs = %v, want %v", got, want)
		}
		for i := range want {
			if got[i].String() != want[i] {
				t.Errorf("AdminAddrs[%d] = %s, want %s", i, got[i], want[i])
			}
		}
	})

	t.Run("empty is allowed", func(t *testing.T) {
		got, err := cfgWith(``).AdminAddrs()
		if err != nil {
			t.Fatalf("AdminAddrs: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("AdminAddrs = %v, want empty", got)
		}
	})

	rejected := []struct {
		name  string
		addrs string
		want  string
	}{
		{name: "v4 prefix", addrs: `"10.0.0.0/8"`, want: "single-address"},
		{name: "v6 prefix", addrs: `"2001:db8::/64"`, want: "single-address"},
		{name: "v4 host bits set", addrs: `"10.1.2.3/24"`, want: "single-address"},
		{name: "bare v4", addrs: `"10.1.2.3"`, want: "safety.admin_allow"},
		{name: "garbage", addrs: `"not-an-address"`, want: "safety.admin_allow"},
		{name: "empty string", addrs: `""`, want: "safety.admin_allow"},
		{name: "prefix on later entry", addrs: `"203.0.113.7/32", "10.0.0.0/8"`, want: "single-address"},
	}
	for _, tc := range rejected {
		t.Run("reject "+tc.name, func(t *testing.T) {
			_, err := cfgWith(tc.addrs).AdminAddrs()
			if err == nil {
				t.Fatalf("AdminAddrs accepted %s", tc.addrs)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// TestLoadConfigMissingFile 确认不存在/不可读的配置是错误而不是"空配置+默认值"：
// 默认值只填空键，绝不会把一个不存在的文件变成一份看似合法的配置。
func TestLoadConfigMissingFile(t *testing.T) {
	_, err := LoadConfig(filepath.Join(t.TempDir(), "nope.toml"))
	if err == nil {
		t.Fatal("LoadConfig accepted a missing file")
	}
}

// TestUninstallPinDir 钉住 -uninstall 的配置无关性：配置读不出来时退回默认 pin
// 目录而不是中止。这是"配置被删/被写坏"这一恢复场景的可执行定义——uninstall 是
// 运维在这种情况下唯一的回收通道，它不能被同一份坏配置挡住。
//
// 例外是 pin.dir 本身（finding A）：它是 os.RemoveAll 的目标，读得出来但过不了
// validPinDir 时返回错误（调用方据此**拒绝**删除），而不是退回默认目录。
//
// fallback 是参数（生产侧传 ebpfplat.DefaultPinDir），所以本用例在 macOS 上也能跑。
func TestUninstallPinDir(t *testing.T) {
	const fallback = "/sys/fs/bpf/knok"

	mustPinDir := func(t *testing.T, path string) string {
		t.Helper()
		got, err := uninstallPinDir(path, fallback)
		if err != nil {
			t.Fatalf("uninstallPinDir(%s) = error %v, want a pin dir", path, err)
		}
		return got
	}

	t.Run("missing file falls back", func(t *testing.T) {
		got := mustPinDir(t, filepath.Join(t.TempDir(), "gone.toml"))
		if got != fallback {
			t.Errorf("uninstallPinDir(missing) = %q, want %q", got, fallback)
		}
	})

	t.Run("malformed toml falls back", func(t *testing.T) {
		// 结构性坏配置（TOML 都解析不了）：回收必须照做。
		got := mustPinDir(t, writeCfg(t, "[keys\npsk = 1\n"))
		if got != fallback {
			t.Errorf("uninstallPinDir(malformed) = %q, want %q", got, fallback)
		}
	})

	t.Run("structurally invalid falls back", func(t *testing.T) {
		// 通过 TOML 解析但过不了结构校验（缺 interfaces）——同样是"起不来"的配置。
		// 回收只做纯解析，所以这种配置连 pin.dir 都读得出来（没有就退回默认）。
		got := mustPinDir(t, writeCfg(t, "[keys]\npsk = \"hex:"+validPSKHex+"\"\n"))
		if got != fallback {
			t.Errorf("uninstallPinDir(no interfaces) = %q, want %q", got, fallback)
		}
	})

	t.Run("valid config uses its pin.dir", func(t *testing.T) {
		body := minCfg + "[pin]\ndir = \"/sys/fs/bpf/knok-e2e\"\n"
		if got := mustPinDir(t, writeCfg(t, body)); got != "/sys/fs/bpf/knok-e2e" {
			t.Errorf("uninstallPinDir(valid) = %q, want /sys/fs/bpf/knok-e2e", got)
		}
	})

	t.Run("valid config without pin.dir uses the parsed default", func(t *testing.T) {
		// 配置有效但没写 [pin]：用 LoadConfig 填的默认值（与 fallback 同值，
		// 但这条路径证明它来自配置的默认填充，而不是"配置读失败"）。
		if got := mustPinDir(t, writeCfg(t, minCfg)); got != fallback {
			t.Errorf("uninstallPinDir(default) = %q, want %q", got, fallback)
		}
	})

	t.Run("bad psk and bad durations do not block clean-up", func(t *testing.T) {
		// PSK 与时长不是纯解析的一部分：这类配置能让 run() 退出 2，但 -uninstall
		// 必须照常工作，并使用配置里的 pin.dir。
		body := "[keys]\npsk = \"deadbeef\"\n[interfaces]\nmode = \"explicit\"\nexplicit = [\"lo\"]\n" +
			"[policy]\nmax_ttl = \"5minutes\"\n[pin]\ndir = \"/sys/fs/bpf/knok-e2e\"\n"
		if got := mustPinDir(t, writeCfg(t, body)); got != "/sys/fs/bpf/knok-e2e" {
			t.Errorf("uninstallPinDir(bad psk/duration) = %q, want /sys/fs/bpf/knok-e2e", got)
		}
	})

	t.Run("unsafe pin.dir is refused, not silently replaced", func(t *testing.T) {
		// finding A 的核心场景：pin.dir 少写了 /knok。这里必须报错（调用方据此
		// 拒绝删除），绝不能被当成"清理默认目录"的许可。
		body := minCfg + "[pin]\ndir = \"/sys/fs/bpf\"\n"
		got, err := uninstallPinDir(writeCfg(t, body), fallback)
		if err == nil {
			t.Fatalf("uninstallPinDir(unsafe) = %q, nil; want an error so the caller refuses to delete", got)
		}
		if got != "" {
			t.Errorf("uninstallPinDir(unsafe) returned dir %q alongside the error; want no usable dir", got)
		}
		if !strings.Contains(err.Error(), "pin.dir") {
			t.Errorf("error %q does not mention pin.dir", err)
		}
	})
}

// TestLoadConfigRejectsUnsafePinDir 钉住 finding A 的第一道闸：配置期就拒绝
// 不可能安全清理的 pin.dir。判据本身由 TestValidPinDir 逐项钉住，这里只证明
// LoadConfig 真的用了它（且在任何内核状态被触碰之前失败）。
//
// 空字符串不在此列：与其它字段一样，空键先被默认值填成 /sys/fs/bpf/knok
// （默认值本身必须过判据，见 TestLoadConfigDefaults）。
func TestLoadConfigRejectsUnsafePinDir(t *testing.T) {
	for _, dir := range []string{"/", ".", "/sys", "sys/fs/bpf", "/sys/fs/bpf", "/sys/fs/bpf/.."} {
		t.Run("reject "+dir, func(t *testing.T) {
			body := minCfg + "[pin]\ndir = " + tomlString(dir) + "\n"
			if _, err := LoadConfig(writeCfg(t, body)); err == nil {
				t.Fatalf("LoadConfig accepted pin.dir = %q (a plausible typo would remove every other tool's pins as root)", dir)
			}
		})
	}
	t.Run("accept deep paths", func(t *testing.T) {
		for _, dir := range []string{"/sys/fs/bpf/knok", "/sys/fs/bpf/knok-e2e"} {
			body := minCfg + "[pin]\ndir = " + tomlString(dir) + "\n"
			cfg, err := LoadConfig(writeCfg(t, body))
			if err != nil {
				t.Fatalf("LoadConfig rejected %q: %v", dir, err)
			}
			if cfg.Pin.Dir != dir {
				t.Errorf("pin.dir = %q, want %q", cfg.Pin.Dir, dir)
			}
		}
	})
}

// TestValidPinDir 是判据本身的表驱动单测（纯函数，任意平台可跑）。
// 合法的只有"看起来像 <root>/<leaf>"、且不是默认 pin 目录祖先的绝对路径。
func TestValidPinDir(t *testing.T) {
	tests := []struct {
		dir  string
		want bool
	}{
		{"/sys/fs/bpf/knok", true},
		{"/sys/fs/bpf/knok-e2e", true},
		{"/var/lib/knok", true}, // 自定义位置合法：判据只保证不是 ±1 级笔误
		{"/", false},
		{".", false},
		{"/sys", false},
		{"sys/fs/bpf", false},
		{"", false},
		{"relative/dir", false},
		{"..", false},
		{"//", false},
		// finding A 的原始场景：少写最后一级（元素计数抓不到它，祖先判据抓住）。
		{"/sys/fs/bpf", false},
		// 原始路径里的 . / .. 分量：Clean 会解析掉它们（/sys/fs/bpf/.. → /sys/fs），
		// 删除目标就不是写下来的那个了——一律拒绝。
		{"/sys/fs/bpf/..", false},
		{"/sys/fs/bpf/./knok", false},
	}
	for _, tc := range tests {
		t.Run(tc.dir, func(t *testing.T) {
			if got := validPinDir(tc.dir); got != tc.want {
				t.Errorf("validPinDir(%q) = %v, want %v", tc.dir, got, tc.want)
			}
		})
	}
}

// tomlString 渲染一个 TOML 字符串字面量（路径里不会有引号/反斜杠，够用）。
func tomlString(s string) string { return `"` + s + `"` }

// TestLoadConfigRejectsNonPositiveDurations 钉住 ride-along 修复：能解析但 <= 0
// 的时长必须在配置期拒绝。零 TTL 的实害是**静默**的：包能穿过管线（只有
// msg.TTL==0 才被拒），cap 到 max_ttl=0 后授权立刻过期，而审计里是一条授权成功。
func TestLoadConfigRejectsNonPositiveDurations(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"max_ttl zero", minCfg + "[policy]\nmax_ttl = \"0s\"\n"},
		{"max_ttl negative", minCfg + "[policy]\nmax_ttl = \"-30s\"\n"},
		{"ts_window zero", minCfg + "[policy]\nts_window = \"0\"\n"},
		{"ts_window negative", minCfg + "[policy]\nts_window = \"-1m\"\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadConfig(writeCfg(t, tc.body))
			if err == nil {
				t.Fatal("LoadConfig accepted a non-positive duration")
			}
			if !strings.Contains(err.Error(), "must be > 0") {
				t.Errorf("error %q does not explain the > 0 requirement", err)
			}
		})
	}
	// 语法错误仍留给 Durations（错误文案与位置固定），所以这一条必须仍然能
	// 通过 LoadConfig——否则 TestDurationsRejectsBadUnit 的路径就没人走了。
	t.Run("syntax errors still deferred to Durations", func(t *testing.T) {
		cfg, err := LoadConfig(writeCfg(t, minCfg+"[policy]\nmax_ttl = \"5minutes\"\n"))
		if err != nil {
			t.Fatalf("LoadConfig rejected an unparseable duration (should defer to Durations): %v", err)
		}
		if _, _, err := cfg.Durations(); err == nil {
			t.Fatal("Durations accepted \"5minutes\"")
		}
	})
}

// TestPolicyWarnings 钉住 finding D 的两条启动期警告：受保护端口不在
// allowed_ports 里（装了 drop 却没人能拿到授权 = 静默远程锁死），以及
// allowed_ports 为空（任何敲门都只会得到 reject_reason=policy）。
func TestPolicyWarnings(t *testing.T) {
	cfgOf := func(t *testing.T, protected, allowed string) *Config {
		t.Helper()
		body := minCfg + "[listen]\nprotected_ports = [" + protected + "]\n" +
			"[policy]\nallowed_ports = [" + allowed + "]\n"
		cfg, err := LoadConfig(writeCfg(t, body))
		if err != nil {
			t.Fatalf("LoadConfig: %v", err)
		}
		return cfg
	}

	t.Run("protected port outside allowed_ports warns", func(t *testing.T) {
		ws := policyWarnings(cfgOf(t, "22, 22222", "22222"))
		if len(ws) != 1 || !strings.Contains(ws[0], "22") {
			t.Fatalf("warnings = %q, want exactly one mentioning port 22", ws)
		}
	})

	t.Run("empty allowed_ports warns", func(t *testing.T) {
		ws := policyWarnings(cfgOf(t, "22", ""))
		// 两条都该出现：端口 22 没被允许 + allowed_ports 为空。
		if len(ws) != 2 {
			t.Fatalf("warnings = %q, want 2 (empty allowed_ports + port 22 outside it)", ws)
		}
	})

	t.Run("consistent config is silent", func(t *testing.T) {
		if ws := policyWarnings(cfgOf(t, "22, 22222", "22, 22222")); len(ws) != 0 {
			t.Fatalf("warnings = %q, want none", ws)
		}
	})

	t.Run("no protected ports is silent", func(t *testing.T) {
		// 只有 SPA 端口、没有受保护端口：没有任何东西会被永久 drop，不该吵。
		if ws := policyWarnings(cfgOf(t, "", "22")); len(ws) != 0 {
			t.Fatalf("warnings = %q, want none", ws)
		}
	})
}

func decodeHex(t *testing.T, s string) [32]byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		t.Fatalf("bad test fixture %q: %v", s, err)
	}
	var k [32]byte
	copy(k[:], b)
	return k
}

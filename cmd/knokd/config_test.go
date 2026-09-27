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

// Package auth 实现 SPA 验证管线。M2 为 PSK 版，M3 替换为 Ed25519/X25519。
package auth

import (
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/zhouyu0615/knok/internal/core/ports"
	"github.com/zhouyu0615/knok/pkg/protocol"
)

type Config struct {
	PSK          [32]byte
	AllowedPorts []uint16
	MaxTTL       time.Duration
	TSWindow     time.Duration // 时间戳容忍窗口，默认 300s
}

type Pipeline struct {
	cfg   Config
	clock ports.Clock
	seen  *nonceCache
}

func NewPipeline(cfg Config, clock ports.Clock) *Pipeline {
	if cfg.TSWindow == 0 {
		cfg.TSWindow = 300 * time.Second
	}
	return &Pipeline{cfg: cfg, clock: clock, seen: newNonceCache(clock)}
}

// Evaluate 按固定顺序验证候选包，返回决策。
//
// 顺序（安全关键）：结构检查（长度/魔数/版本，位于 DecodePSK）→ 认证
// （DecodePSK 的 AEAD 门，先认证后解密）→ 时间戳窗口 → 重放缓存 → 策略 → TTL 封顶。
func (p *Pipeline) Evaluate(pkt ports.CandidatePacket) ports.Decision {
	reject := func(reason string) ports.Decision {
		return ports.Decision{SrcIP: pkt.SrcIP, RejectReason: reason}
	}
	msg, err := protocol.DecodePSK(pkt.Payload, p.cfg.PSK)
	if err != nil {
		if errors.Is(err, protocol.ErrAuth) {
			return reject("auth_failed")
		}
		return reject("bad_packet")
	}
	now := p.clock.Now()
	ts := time.Unix(int64(msg.TS), 0)
	if ts.Before(now.Add(-p.cfg.TSWindow)) || ts.After(now.Add(p.cfg.TSWindow)) {
		return reject("clock_skew")
	}
	if !p.seen.Add(msg.Nonce, now.Add(p.cfg.TSWindow*2)) {
		return reject("replay")
	}
	if len(msg.Ports) == 0 || msg.TTL == 0 {
		return reject("policy")
	}
	for _, port := range msg.Ports {
		if !slices.Contains(p.cfg.AllowedPorts, port) {
			return reject("policy")
		}
	}
	ttl := time.Duration(msg.TTL) * time.Second
	if ttl > p.cfg.MaxTTL {
		ttl = p.cfg.MaxTTL
	}
	return ports.Decision{Allowed: true, SrcIP: pkt.SrcIP, Ports: msg.Ports, TTL: ttl}
}

// nonceCache 是带过期清理的重放缓存（TSWindow*2 后惰性清除）。
//
// 过期判断必须与写入 expiry 时使用同一个时钟：entry 由注入的 Clock 打上
// expiry，清理也只能用同一个 Clock 比较，否则（测试用 FakeClock、真实系统时间
// 与之偏离时）entry 会在重复检查之前被误清理，replay 检测静默失效。
//
// **已知限制（M2，final review finding B）：缓存只在进程内存里，进程重启即清空。**
// 于是"重放"，这个缓存本该拦住的攻击，有一个确定的绕过路径：捕获一个合法 knock
// 后等 daemon 重启，再把同一个包原样打一次。时间戳仍在容忍窗口内（TSWindow，
// 默认 300s），nonce 在内存里已无记录，管线因此放行——而授权是按**源 IP** 写入
// allowlist 的，授权对象变成重放者自己的地址（source-IP rebinding），它拿到一份
// 与原始请求等长的访问权。暴露窗口 = 捕获者可重放 + daemon 在该窗口内重启过。
//
// M3 把这张表换成 pinned/持久化的存储（spec §3.3 第 4 步的 nonce 表），让重启
// 不再丢失重放记录。这里刻意不"顺手"加持久化：M2 是薄端到端切片，先把这个限制
// 写清楚（spec §11 与 README 各有一条），比半边实现更安全。
type nonceCache struct {
	mu   sync.Mutex
	seen map[[16]byte]time.Time
	now  func() time.Time
}

func newNonceCache(clock ports.Clock) *nonceCache {
	return &nonceCache{seen: map[[16]byte]time.Time{}, now: clock.Now}
}

// Add 报告 nonce 是否首次出现；重复出现返回 false。
func (c *nonceCache) Add(nonce [16]byte, expiry time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	for k, exp := range c.seen { // 惰性清理，量小（受 TSWindow 限制）
		if exp.Before(now) {
			delete(c.seen, k)
		}
	}
	if _, dup := c.seen[nonce]; dup {
		return false
	}
	c.seen[nonce] = expiry
	return true
}

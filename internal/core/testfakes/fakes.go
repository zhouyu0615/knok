// Package testfakes 提供 core 层接口的内存实现，用于非 Linux 环境的单元测试。
package testfakes

import (
	"net/netip"
	"sync"
	"time"

	"github.com/zhouyu0615/knok/internal/core/ports"
)

type FakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func NewFakeClock(start time.Time) *FakeClock { return &FakeClock{t: start} }
func (c *FakeClock) Now() time.Time           { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *FakeClock) Set(t time.Time)          { c.mu.Lock(); defer c.mu.Unlock(); c.t = t }
func (c *FakeClock) Advance(d time.Duration)  { c.mu.Lock(); defer c.mu.Unlock(); c.t = c.t.Add(d) }

type key struct {
	ip   netip.Addr
	port uint16
}

type MemAllowlist struct {
	mu      sync.Mutex
	entries map[key]ports.Entry
	now     ports.Clock
}

func NewMemAllowlist(clock ports.Clock) *MemAllowlist {
	return &MemAllowlist{entries: map[key]ports.Entry{}, now: clock}
}

func (m *MemAllowlist) Grant(ip netip.Addr, port uint16, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries[key{ip, port}] = ports.Entry{IP: ip, Port: port, ExpiresAt: m.now.Now().Add(ttl)}
	return nil
}

func (m *MemAllowlist) GrantForever(ip netip.Addr, port uint16) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries[key{ip, port}] = ports.Entry{IP: ip, Port: port, Forever: true}
	return nil
}

func (m *MemAllowlist) Revoke(ip netip.Addr, port uint16) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.entries, key{ip, port})
	return nil
}

func (m *MemAllowlist) List() ([]ports.Entry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]ports.Entry, 0, len(m.entries))
	now := m.now.Now()
	for k, e := range m.entries {
		if !e.Forever && e.ExpiresAt.Before(now) {
			delete(m.entries, k) // 惰性过期
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

// Has 供测试断言使用。
func (m *MemAllowlist) Has(ip netip.Addr, port uint16) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.entries[key{ip, port}]
	if !ok {
		return false
	}
	return e.Forever || e.ExpiresAt.After(m.now.Now())
}

type ChanSource struct {
	ch   chan ports.CandidatePacket
	once sync.Once
}

func NewChanSource(buf int) *ChanSource {
	return &ChanSource{ch: make(chan ports.CandidatePacket, buf)}
}
func (s *ChanSource) Send(p ports.CandidatePacket)          { s.ch <- p }
func (s *ChanSource) Packets() <-chan ports.CandidatePacket { return s.ch }
func (s *ChanSource) Close() error                          { s.once.Do(func() { close(s.ch) }); return nil }

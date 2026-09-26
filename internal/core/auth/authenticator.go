package auth

import (
	"context"
	"log/slog"

	"github.com/zhouyu0615/knok/internal/core/ports"
)

type Authenticator struct {
	src   ports.PacketSource
	pipe  *Pipeline
	allow ports.Allowlist
	audit ports.AuditSink
}

func NewAuthenticator(src ports.PacketSource, p *Pipeline, al ports.Allowlist, sink ports.AuditSink) *Authenticator {
	return &Authenticator{src: src, pipe: p, allow: al, audit: sink}
}

// Run 阻塞消费候选包直到 ctx 取消或 source 关闭。
func (a *Authenticator) Run(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case pkt, ok := <-a.src.Packets():
			if !ok {
				return nil
			}
			d := a.pipe.Evaluate(pkt)
			if d.Allowed {
				for _, port := range d.Ports {
					if err := a.allow.Grant(pkt.SrcIP, port, d.TTL); err != nil {
						slog.Error("allowlist grant failed", "ip", pkt.SrcIP, "port", port, "err", err)
						d.Allowed, d.RejectReason = false, "grant_failed"
					}
				}
			}
			a.audit.Emit(d, pkt)
		}
	}
}

// LogAuditSink 把 Decision 输出为结构化日志（JSON lines via slog）。
type LogAuditSink struct{ Logger *slog.Logger }

func (s LogAuditSink) Emit(d ports.Decision, pkt ports.CandidatePacket) {
	attrs := []any{"src_ip", pkt.SrcIP.String(), "dst_port", pkt.DstPort,
		"allowed", d.Allowed, "reason", d.RejectReason}
	if d.Allowed {
		attrs = append(attrs, "ports", d.Ports, "ttl", d.TTL.String())
		s.Logger.Info("spa_grant", attrs...)
		return
	}
	s.Logger.Warn("spa_reject", attrs...)
}

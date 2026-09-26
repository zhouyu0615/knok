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
				// 首个 Grant 失败即停止：后续端口不再尝试，已成功的授权**不回滚**
				// （它可能来自同一客户端早先的包）。决策必须真实反映本次实际授权的子集。
				granted := make([]uint16, 0, len(d.Ports))
				for _, port := range d.Ports {
					if err := a.allow.Grant(pkt.SrcIP, port, d.TTL); err != nil {
						slog.Error("allowlist grant failed", "ip", pkt.SrcIP, "port", port, "err", err)
						d.Allowed, d.RejectReason = false, "grant_failed"
						break
					}
					granted = append(granted, port)
				}
				if !d.Allowed {
					d.Ports = granted // 非 nil 空切片：本次评估实际授权的端口子集
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
	// 部分授权的拒绝也必须可见：spa_reject 行附带本次实际打开的端口子集。
	if len(d.Ports) > 0 {
		attrs = append(attrs, "granted_ports", d.Ports)
	}
	s.Logger.Warn("spa_reject", attrs...)
}

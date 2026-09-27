package main

import (
	"context"
	"fmt"
	"log/slog"
)

// abortIfShuttingDown 是启动序列最后两步（[5] admin_allow 放行、[6] 安装防火墙）
// 之前的闸门：ctx 已被 SIGINT/SIGTERM 取消时返回非 nil，调用方据此**不**继续。
//
// 为什么这两步需要额外的闸门：signal.NotifyContext 只是给 ctx 打标记，
// authenticator.Run 会随之返回，但 run() 不会——它会一路走到 step [6]。于是可以
// 出现"drop 规则装好了、授权服务已经停了"的状态：受保护端口对所有人（包括刚刚
// 敲门成功的客户端）静默丢包，正是本文件开头反复警告的"锁上门却没有钥匙"。
// 闸门把这一支挡住：在装规则之前返回非 nil，进程非零退出（退出码 3，不是 2——
// 这不是用户可修的配置问题）。
//
// 竞态窗口（必须说明，不能假装不存在）：ctx.Err() 与 EnsureProtectedPorts 之间
// 信号仍可能到达，那一支会装上规则、随即走正常关闭路径。内核里没有"带条件的原子
// 安装"，而先屏蔽信号再安装会把"立刻停止"变成"先装规则再停"——两种取舍都留下某种
// 窗口，这里选择把窗口压到一次原子读那么小，并让它的后果与运行期关闭语义一致
// （表保留，由 -uninstall 或下一次启动接管）。真正危险的组合是"规则装上而授权通路
// 从未就绪"，那一支现在需要信号早于闸门到达，已被挡住。
//
// 本文件刻意没有构建标签：判定与内核无关，因此它可以被单测确定性地钉住（不需要
// root、不需要 bpffs），而不是只能靠代码审阅。
func abortIfShuttingDown(ctx context.Context) error {
	err := ctx.Err()
	if err == nil {
		return nil
	}
	// 大声报出来是刻意的：日志里必须能读出"为什么这台机器上没有装防火墙"，
	// 否则运维只能看到一个非零退出码。
	slog.Error("shutdown signal received during startup: no firewall rules were installed (fail-open)")
	return fmt.Errorf("startup aborted by signal before the firewall was installed: %w", err)
}

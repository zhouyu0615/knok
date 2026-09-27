package main

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// TestAbortIfShuttingDown 钉住 step [5]/[6] 前的信号闸门：ctx 已被取消时必须在
// 安装防火墙之前返回错误（进程非零退出），未取消时是零成本的空操作。
//
// 它是本任务里少见的"信号路径可以被确定性验证"的部分：闸门与内核无关，所以这个
// 用例在 macOS 与 Linux 上都执行，不需要 root、也不需要 bpffs。
func TestAbortIfShuttingDown(t *testing.T) {
	t.Run("running is a no-op", func(t *testing.T) {
		if err := abortIfShuttingDown(context.Background()); err != nil {
			t.Fatalf("abortIfShuttingDown(background) = %v, want nil", err)
		}
	})

	t.Run("cancelled aborts non-config error", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err := abortIfShuttingDown(ctx)
		if err == nil {
			t.Fatal("abortIfShuttingDown(cancelled) = nil，drop 规则会在授权通路已停止后被装上")
		}
		if !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v，应当可以用 errors.Is 判定为 context.Canceled", err)
		}
		// 必须是"非配置错"：main 据此退出码 3。若它落在 configError 上，退出码会
		// 变成 2（"运维改配置就能修"），把一次信号误导成一次配置事故。
		var cerr *configError
		if errors.As(err, &cerr) {
			t.Errorf("err = %T，信号中止不是配置错（退出码必须是非零且非 2）", err)
		}
		if !strings.Contains(err.Error(), "firewall") {
			t.Errorf("err = %q，日志必须能读出「防火墙没装」", err)
		}
	})

	t.Run("deadline exceeded also aborts", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 0)
		defer cancel()
		if err := abortIfShuttingDown(ctx); !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("abortIfShuttingDown(timed out) = %v, want context.DeadlineExceeded", err)
		}
	})
}

//go:build linux

// Command knokd 是 knok 的组装根：把 eBPF 数据面、SPA 验证管线、allowlist 与
// nftables 防火墙接成一个进程。
//
// 本文件最重要的东西不是它做了什么，而是**它做这些事的顺序**（spec §6）：
//
//	[1] 配置 + 密钥材料（失败 → 退出，不动任何内核状态）
//	[2] 加载/创建 pinned maps（复用上次运行的数据面）
//	[3] 把程序 attach 到配置里的每一个网卡
//	[4] ringbuf 消费者 + 验证管线启动（授权通路就绪）
//	[5] 写入 admin_allow 永久放行（逃生通道）
//	[6] 最后一步才 EnsureProtectedPorts 安装 drop 规则
//
// 这个顺序就是整个设计的安全前提：**防火墙是最后一条腿**。前五步任何一步失败都
// 不会装上 drop 规则，失败是 fail-open 的——knokd 起不来时，机器的可达性与没有
// knok 时一样，最坏结果是"没被保护"，而不是"把自己锁在门外"。反过来，如果把
// 第 6 步提前，一次配置笔误就能让守护进程在授权通路还没起来时先丢包。
//
// 因此下面每一步的失败路径都必须**早于**第 6 步返回（非零退出码 + 大声报错），
// 且第 6 步成功后 run() 再也没有任何非 nil 返回——见文件末尾的自检清单。
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/zhouyu0615/knok/internal/core/auth"
	"github.com/zhouyu0615/knok/internal/core/ports"
	ebpfplat "github.com/zhouyu0615/knok/internal/platform/ebpf"
	knoknft "github.com/zhouyu0615/knok/internal/platform/nftables"
	"github.com/zhouyu0615/knok/pkg/protocol"
)

// 退出码约定（Task 9 的对外契约）：0 正常；2 配置错（用户可修）；3 内核/权限/
// 数据面不可用（环境问题）。区分二者的价值在于"谁该去看"——2 是运维改配置，
// 3 是换内核/提权。
const (
	exitConfig = 2
	exitKernel = 3
)

func main() {
	cfgPath := flag.String("config", "/etc/knok/knokd.toml", "config file")
	uninstall := flag.Bool("uninstall", false, "remove inet knok table and pinned state, then exit")
	metricsAddr := flag.String("metrics", "127.0.0.1:9601", "prometheus metrics address ('' disables)")
	flag.Parse()

	// 日志必须是第一个就位的东西：LogAuditSink 持有这个 logger（nil 会 panic），
	// 而"失败要大声"是 spec §6 的要求——JSON 到 stdout，交给 journald 或采集器。
	// 部署上没有任何一处日志是给人肉 grep 的。
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	if *uninstall {
		mustUninstall(*cfgPath)
		return
	}
	if err := run(*cfgPath, *metricsAddr); err != nil {
		logger.Error("fatal", "err", err)
		var cerr *configError
		if errors.As(err, &cerr) {
			os.Exit(exitConfig)
		}
		os.Exit(exitKernel)
	}
}

// configError 标记"用户可修"的失败（配置解析/校验/接口不存在）。main 用它把
// 退出码分成 2 与 3；errors.As 穿透 fmt.Errorf 的包装，所以 run() 内部怎么包都行。
type configError struct{ err error }

func (e *configError) Error() string { return e.err.Error() }
func (e *configError) Unwrap() error { return e.err }

// run 执行完整启动序列并在前台阻塞到进程被信号终止。
//
// 返回非 nil 等价于"knokd 没能进入服务态"：调用方据此非零退出。唯一能让它带着
// 已安装的防火墙返回的路径是信号触发的正常关闭（返回 nil）——所以不存在"装了
// drop 规则但进程立刻退出"的组合。
func run(cfgPath, metricsAddr string) error {
	// [1] 配置与密钥（失败不动内核状态）。
	// ResolveInterfaces 也排在这里：它是只读的 netlink 查询，把"网卡名写错"这类
	// 笔误挡在加载 maps 之前——否则会留下一个没有附着、却已经动过内核的中间状态。
	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		return &configError{err}
	}
	psk, err := cfg.PSK()
	if err != nil {
		return &configError{err}
	}
	maxTTL, tsWindow, err := cfg.Durations()
	if err != nil {
		return &configError{err}
	}
	adminAddrs, err := cfg.AdminAddrs()
	if err != nil {
		return &configError{err}
	}
	ifaces, err := ebpfplat.ResolveInterfaces(cfg.Interfaces.Explicit)
	if err != nil {
		return &configError{err}
	}
	slog.Info("config loaded",
		"config", cfgPath, "spa_port", cfg.Listen.SPAUDPPort,
		"protected_ports", cfg.Listen.ProtectedPorts, "allowed_ports", cfg.Policy.AllowedPorts,
		"interfaces", cfg.Interfaces.Explicit, "pin_dir", cfg.Pin.Dir,
		"max_ttl", maxTTL.String(), "ts_window", tsWindow.String(),
		"admin_allow", cfg.Safety.AdminAllow)

	// [2] maps（pin 复用 → 重启保授权）。
	// rlimit.RemoveMemlock 必须在加载对象之前：内核 < 5.11 上 map/程序的内存是
	// 从 RLIMIT_MEMLOCK 里扣的，默认 64KB 加载必失败，而 spec 声称支持 ≥ 5.8。
	// 失败不中止——它在一个不需要它的内核上失败是正常的（5.11+ 已改为 memcg 记账），
	// 此时加载照样能成功；真要失败，LoadObjects 会给出更准确的错误。
	if err := rlimit.RemoveMemlock(); err != nil {
		slog.Warn("rlimit: could not raise RLIMIT_MEMLOCK (fine on kernels >= 5.11)", "err", err)
	}
	objs, err := ebpfplat.LoadObjects(cfg.Pin.Dir)
	if err != nil {
		return err
	}
	defer objs.Close()
	if err := ebpfplat.WriteCfg(objs, uint32(cfg.Listen.SPAUDPPort),
		uint32(protocol.MinPSKPktLen), uint32(protocol.MaxPktLen)); err != nil {
		return err
	}

	// [3] attach 全部接口。
	// 中途失败**不回滚**已成功的附着：这些附着本身不丢任何包（数据面只负责打
	// mark），而第 6 步没走到，所以此刻机器是 fail-open 的；pin 也让下次启动直接
	// 复用（TCX）。回滚反而会把"崩溃存活"的 pin 删掉，多一次无谓的抖动。
	backend := ebpfplat.DetectBackend()
	slog.Info("backend", "kind", backend.Kind())
	for _, l := range ifaces {
		if _, err := backend.Attach(l.Attrs().Index, objs.KnokIngress, cfg.Pin.Dir); err != nil {
			return fmt.Errorf("attach %s: %w", l.Attrs().Name, err)
		}
		slog.Info("attached", "iface", l.Attrs().Name, "backend", backend.Kind())
	}

	// [4] 授权通路就绪：ringbuf source + pipeline + authenticator。
	// 从这里开始"敲门能开门"这件事成立——第 6 步的 drop 规则才有意义。
	clock := realClock{}
	src, err := ebpfplat.NewRingbufSource(objs.SpaEvents, 256)
	if err != nil {
		return err
	}
	allowlist := ebpfplat.NewMapAllowlist(objs.Allowlist, clock)
	pipeline := auth.NewPipeline(auth.Config{
		PSK: psk, AllowedPorts: cfg.Policy.AllowedPorts,
		MaxTTL: maxTTL, TSWindow: tsWindow,
	}, clock)
	authenticator := auth.NewAuthenticator(src, pipeline, allowlist,
		auth.LogAuditSink{Logger: slog.Default()})

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	runDone := make(chan error, 1)
	go func() { runDone <- authenticator.Run(ctx) }()
	slog.Info("authorization path ready", "interfaces", cfg.Interfaces.Explicit)

	// [5] 逃生通道：admin_allow 永久放行（必须在防火墙之前！）。
	// 顺序是安全相关的：管理地址的 GrantForever 一旦落在 drop 规则之后，中间那段
	// 窗口里"唯一能进来的人"会被自己的防火墙挡住——而这正是最需要它可用的时刻。
	for _, p := range cfg.Listen.ProtectedPorts {
		for _, a := range adminAddrs {
			if err := allowlist.GrantForever(a, p); err != nil {
				return fmt.Errorf("admin_allow %s:%d: %w", a, p, err)
			}
			slog.Info("admin_allow granted forever", "addr", a.String(), "port", p)
		}
	}

	// [6] 最后一步才装防火墙（此前任何失败都 fail-open）。
	// 这是全文件唯一写内核裁决状态的地方，也是启动序列的终点：它成功后 run 不再
	// 有任何非 nil 返回。
	fw := knoknft.New()
	if err := fw.EnsureProtectedPorts(cfg.Listen.ProtectedPorts, cfg.Listen.SPAUDPPort); err != nil {
		return fmt.Errorf("firewall: %w", err)
	}
	slog.Info("firewall installed", "protected", cfg.Listen.ProtectedPorts,
		"spa_port", cfg.Listen.SPAUDPPort)

	if metricsAddr != "" {
		go serveMetrics(metricsAddr, objs)
	}

	<-ctx.Done()
	// 关闭语义（spec §6）：**fail-closed**。eBPF 程序留在网卡上、nftables 表留在
	// 内核里——这样即使 knokd 死了，已授权的流量与"受保护端口默认 drop"的裁决都
	// 还成立。没有 SIGTERM 时刻的"顺手清理"，因为那个窗口正是最不安全的。
	slog.Info("shutting down; eBPF stays attached, nftables table retained (fail-closed)")
	// ctx 取消才是 ringbuf 消费者的退出口（RingbufSource 刻意不关闭 channel），
	// 所以先等它自然结束再收尾：既不依赖 channel 关闭，也不会卡住。
	src.Close()
	if err := <-runDone; err != nil && !errors.Is(err, context.Canceled) {
		slog.Warn("authenticator stopped", "err", err)
	}
	return nil
}

// serveMetrics 暴露数据面的 eBPF 计数器（Task 7 的 stats map）。
//
// 指标服务是旁路：绑定失败或写入失败都只影响可观测性，绝不影响授权与丢包裁决，
// 因此这里把错误打成 warn 后就地返回，不让它有机会升级成进程级失败。
func serveMetrics(addr string, objs *ebpfplat.KnokObjects) {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		st, err := ebpfplat.ReadStats(objs)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// 顺序即 ARRAY map 的槽位（StTotal…StRingbufDrop），与 types.go 的常量一致。
		names := []string{"total", "allow_hit", "allow_expired", "candidate", "rate_drop", "ringbuf_drop"}
		fmt.Fprintln(w, "# HELP knok_packets_total eBPF dataplane counters")
		fmt.Fprintln(w, "# TYPE knok_packets_total counter")
		for i, n := range names {
			fmt.Fprintf(w, "knok_packets_total{slot=%q} %d\n", n, st[i])
		}
	})
	if err := http.ListenAndServe(addr, mux); err != nil {
		slog.Warn("metrics server stopped", "addr", addr, "err", err)
	}
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// mustUninstall 是 -uninstall 的完整回收路径：拆表 → 摘附着 → 删 pin 目录。
//
// 顺序与安装相反，且**防火墙先拆**是刻意的：只要 inet knok 表还在，受保护端口
// 无 mark 即 drop。若先摘数据面再拆表，中间窗口里 drop 规则仍在、却没有任何东西
// 能打 mark——那是"看着有授权、实际全丢"的坏 fail-closed，比不装规则更糟。
//
// 每步都尽力执行（一步失败不跳过其余），最后统一以退出码 3 报告"回收不完整"：
// 半途而废对运维是隐藏状态，宁愿让脚本红着，也不要让下一个认为"已经清干净了"。
func mustUninstall(cfgPath string) {
	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		slog.Error("uninstall: config", "err", err)
		os.Exit(exitConfig)
	}

	var failed bool
	if err := knoknft.New().Uninstall(); err != nil {
		slog.Error("uninstall: nftables table", "err", err)
		failed = true
	}

	backend := ebpfplat.DetectBackend()
	handles, err := backend.List(cfg.Pin.Dir)
	if err != nil {
		slog.Error("uninstall: list attachments", "dir", cfg.Pin.Dir, "err", err)
		failed = true
	}
	for _, h := range handles {
		// Detach 与 Unpin 都调用是安全的：cilium 的 FD.Close 幂等（第二次是
		// no-op），而 TCX 的存活恰恰依赖"Detach 不删 pin、Unpin 才删 pin"的分工
		// （Ruling 5）。clsact 没有 pin，二者的效果等价（都是删 filter），重复
		// 调用同样无害。
		if err := backend.Detach(h); err != nil {
			slog.Error("uninstall: detach", "iface", h.IfName, "err", err)
			failed = true
		}
		if u, ok := backend.(ebpfplat.Unpinner); ok {
			if err := u.Unpin(h, cfg.Pin.Dir); err != nil {
				slog.Error("uninstall: unpin", "iface", h.IfName, "err", err)
				failed = true
			}
		}
	}

	// pin 目录里同时住着 maps 与 link 的 pin；删目录即回收内核对象（两者的引用
	// 都只由 pin 持有）。目录不存在时 RemoveAll 返回 nil，所以重复 uninstall 是
	// 干净的空操作。
	if err := os.RemoveAll(cfg.Pin.Dir); err != nil {
		slog.Error("uninstall: remove pin dir", "dir", cfg.Pin.Dir, "err", err)
		failed = true
	}

	if failed {
		slog.Error("uninstall incomplete: some kernel state may remain")
		os.Exit(exitKernel)
	}
	slog.Info("uninstalled: nftables table, pinned links and maps removed")
}

var _ ports.Clock = realClock{}

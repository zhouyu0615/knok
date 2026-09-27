.PHONY: all vet test bpf integration e2e corelint

GO ?= go

all: vet corelint test

# 脚手架阶段（以及 M1/M2 的中间状态）仓库内还没有 Go 包：`go vet ./...` 会以
# "matched no packages"、`go test ./pkg/...` 会在目录不存在时以
# "lstat ./pkg/: no such file or directory" 退出 1（Go >=1.21 的行为）。
# 因此按“目录是否存在”逐个筛选待跑的 pattern：缺哪个目录就跳过哪个 pattern，
# 一个都不存在时才空跑通过（partial repo：只有 internal/core 时只跑 internal/core）。
# 这里直接 [ -d ] 判断目录，而不是解析 `go list` 的输出：后者在 go.mod 损坏或包无法
# 加载时输出同样为空，会把真实错误当成“无包”静默放过（旧写法丢弃 stderr 的缺陷）。
#
# 覆盖范围（Ruling 19）：pkg/... 、internal/core/... 之外还必须包含 cmd/...
# （knok 客户端与 knokd 守护进程）与 internal/platform/...（eBPF/nftables/平台适配及
# 其测试）——否则守护进程、平台适配和它们的测试都落在项目门槛之外，`make vet test`
# 绿着而里面有编译不过的包。corelint 仍然只针对 internal/core。
# vet/test/integration 三个目标共用下面这段相同的 dirs 收集逻辑：
# vet 只用它判断“仓库里是否已有 Go 包”，实际命令仍是 `go vet ./...`（递归 pattern 不会
# 因为 ./pkg 不存在而失败）；test/integration 用它决定跑哪些 pattern。
vet:
	@dirs=""; \
	[ -d pkg ] && dirs="$$dirs ./pkg/..."; \
	[ -d internal/core ] && dirs="$$dirs ./internal/core/..."; \
	[ -d internal/platform ] && dirs="$$dirs ./internal/platform/..."; \
	[ -d cmd ] && dirs="$$dirs ./cmd/..."; \
	if [ -z "$$dirs" ]; then echo "vet: no Go packages yet, nothing to vet"; \
	else $(GO) vet ./...; fi

test:
	@dirs=""; \
	[ -d pkg ] && dirs="$$dirs ./pkg/..."; \
	[ -d internal/core ] && dirs="$$dirs ./internal/core/..."; \
	[ -d internal/platform ] && dirs="$$dirs ./internal/platform/..."; \
	[ -d cmd ] && dirs="$$dirs ./cmd/..."; \
	if [ -z "$$dirs" ]; then echo "test: no Go packages yet, nothing to test"; \
	else $(GO) test $$dirs; fi

# 架构守护：internal/core 不得 import 平台库
corelint:
	@deps=$$($(GO) list -deps ./internal/core/... 2>/dev/null | grep -E 'cilium/ebpf|vishvananda/netlink|google/nftables' || true); \
	if [ -n "$$deps" ]; then echo "core isolation violation:"; echo "$$deps"; exit 1; fi

# 以下目标仅在 VPS（Linux）上运行
bpf: bpf/vmlinux.h
	cd internal/platform/ebpf && $(GO) generate ./...

bpf/vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

integration:
	@dirs=""; \
	[ -d pkg ] && dirs="$$dirs ./pkg/..."; \
	[ -d internal/core ] && dirs="$$dirs ./internal/core/..."; \
	[ -d internal/platform ] && dirs="$$dirs ./internal/platform/..."; \
	[ -d cmd ] && dirs="$$dirs ./cmd/..."; \
	if [ -z "$$dirs" ]; then echo "integration: no Go packages yet, nothing to test"; \
	else $(GO) test -tags=integration -count=1 ./...; fi

# M2 端到端验收：在 Linux 上以 root 运行（脚本自己回收进程/表/pin/临时文件）。
# 需要在仓库根执行，`sudo` 不会改变 PATH，go/nc/nft/tc 都必须能找到。
e2e:
	sudo bash scripts/e2e.sh

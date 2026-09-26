.PHONY: all vet test bpf integration e2e corelint

GO ?= go

all: vet corelint test

# 脚手架阶段仓库内还没有 Go 包，`go vet ./...` 与 `go test ./pkg/...` 会以
# "matched no packages" / "no such file or directory" 退出 1（Go >=1.21 的行为）。
# 因此先探测包是否存在：无包时空跑通过，有包时命令与原先完全一致。
vet:
	@pkgs=$$($(GO) list ./... 2>/dev/null || true); \
	if [ -z "$$pkgs" ]; then echo "vet: no Go packages yet, nothing to vet"; \
	else $(GO) vet ./...; fi

test:
	@pkgs=$$($(GO) list ./pkg/... ./internal/core/... 2>/dev/null || true); \
	if [ -z "$$pkgs" ]; then echo "test: no Go packages yet, nothing to test"; \
	else $(GO) test ./pkg/... ./internal/core/...; fi

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
	$(GO) test -tags=integration -count=1 ./...

e2e:
	sudo bash scripts/e2e.sh

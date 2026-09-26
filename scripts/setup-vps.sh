#!/usr/bin/env bash
# 在 Ubuntu 24.04 VPS 上以 root 运行（可安全重复执行，幂等）
set -euo pipefail

GO_VERSION_MIN=1.22 # go.mod 声明的语言版本
GO_VER=1.23.4       # 需要安装时使用的固定版本

# version_ge A B：按版本号比较，A >= B 时返回 0
version_ge() { printf '%s\n%s\n' "$2" "$1" | sort -V -C; }

apt-get update

# 必需工具集：任一缺失都视为致命错误
apt-get install -y clang llvm libelf-dev nftables git make gcc \
    linux-tools-generic linux-tools-common

# 可选：与当前内核 ABI 匹配的 linux-tools（HWE / 云内核常无对应包）以及独立的 bpftool 包。
# 装不上只警告，不中断脚本；bpftool 后续会从 linux-tools-generic 或 PATH 中解析。
apt-get install -y "linux-tools-$(uname -r)" \
    || echo "警告：linux-tools-$(uname -r) 不可用，改用 linux-tools-generic 提供的 bpftool" >&2
apt-get install -y bpftool \
    || echo "警告：bpftool 包不可用，继续在 linux-tools 目录下查找 bpftool" >&2

# Go：已安装且 >= GO_VERSION_MIN 就复用，否则安装固定版本（按 CPU 架构选择 tarball）
go_cur=""
if command -v go >/dev/null 2>&1; then
    go_cur=$(go version 2>/dev/null | awk '{print $3}' | sed 's/^go//' || true)
fi
if [ -z "$go_cur" ] || ! version_ge "$go_cur" "$GO_VERSION_MIN"; then
    go_arch=$(dpkg --print-architecture)
    case "$go_arch" in
    amd64 | arm64) ;;
    *)
        echo "错误：不支持的 CPU 架构 ${go_arch}，请手动安装 Go >= ${GO_VERSION_MIN}" >&2
        exit 1
        ;;
    esac
    echo "安装 Go ${GO_VER}（当前：${go_cur:-未安装}，要求 >= ${GO_VERSION_MIN}）"
    curl -fsSL "https://go.dev/dl/go${GO_VER}.linux-${go_arch}.tar.gz" | tar -C /usr/local -xz
    ln -sf /usr/local/go/bin/go /usr/local/bin/go
    hash -r
fi

# bpftool：优先使用 PATH 中已有的命令；否则在 linux-tools 各 ABI 目录下查找，
# 确认文件存在（可执行）后再建软链，避免 glob 不展开时创建悬空链接并静默成功。
if ! command -v bpftool >/dev/null 2>&1; then
    for bin in /usr/lib/linux-tools/*/bpftool; do
        [ -x "$bin" ] || continue
        ln -sf "$bin" /usr/local/bin/bpftool
        break
    done
    hash -r
fi
if ! command -v bpftool >/dev/null 2>&1; then
    echo "错误：未找到可用的 bpftool。" >&2
    echo "请执行 apt-get install -y bpftool，或从内核源码 tools/bpf/bpftool 编译后放入 PATH。" >&2
    exit 1
fi

nft --version && clang --version | head -1 && go version && bpftool version
echo "VPS 工具链就绪。下一步：make bpf"

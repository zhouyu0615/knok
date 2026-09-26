#!/usr/bin/env bash
# 在 Ubuntu 24.04 VPS 上以 root 运行一次
set -euo pipefail
apt-get update
apt-get install -y clang llvm libelf-dev linux-tools-generic linux-tools-$(uname -r) \
    nftables git make gcc
# Go（若未安装）
if ! command -v go >/dev/null; then
    GO_VER=1.23.4
    curl -fsSL "https://go.dev/dl/go${GO_VER}.linux-amd64.tar.gz" | tar -C /usr/local -xz
    ln -sf /usr/local/go/bin/go /usr/local/bin/go
fi
# bpftool 可能叫 bpftool 或在 linux-tools 路径下，确认可用
command -v bpftool || ln -sf /usr/lib/linux-tools/*/bpftool /usr/local/bin/bpftool
nft --version && clang --version | head -1 && go version && bpftool version
echo "VPS 工具链就绪。下一步：make bpf"
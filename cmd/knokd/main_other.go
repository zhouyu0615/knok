//go:build !linux

package main

import (
	"fmt"
	"os"
)

// 非 Linux 构建只提供"能编译"这一件事：eBPF（cilium/ebpf 的 attach 路径）、
// nftables 与 bpffs 都是 Linux 专属，knokd 在别的平台上没有任何可行的执行路径。
//
// 保留一个 main 而不是让包缺 main 是必须的：package main 没有 func main 会让
// `go build ./...` 在 macOS 上以 "function main is undeclared in the main
// package" 失败（链接期的报错，不是编译期），而"macOS 上 go build ./... 绿"
// 是本仓库的全局约束。这里与 nftables 的 firewall_other.go 同一套做法：明确
// 失败，绝不静默成功。
func main() {
	fmt.Fprintln(os.Stderr, "knokd: linux only (eBPF, nftables and bpffs are Linux-specific)")
	os.Exit(3)
}

//go:build linux

package ebpfplat

// 在 VPS 上运行：make bpf
// 需要 bpf/vmlinux.h（bpftool 生成，见 Makefile）。
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall" knok ../../../bpf/knok_ingress.c -- -I../../../bpf

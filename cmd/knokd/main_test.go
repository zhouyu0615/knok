//go:build linux

package main

import (
	"errors"
	"path/filepath"
	"strconv"
	"testing"
)

// validPSK 是 main_test.go 里用的合法密钥串（与 config_test.go 同一夹具）。
const validPSK = "hex:" + validPSKHex

// ifaceBlock 是配置里唯一必需的结构块。
const ifaceBlock = "[interfaces]\nmode = \"explicit\"\nexplicit = [\"lo\"]\n"

// TestRunConfigErrorsAreConfigErrors 钉住启动序列 [1] 的对外契约：配置层的任何
// 失败都必须被归类为 configError（main 据此退出码 2），而不是掉进 exit 3。
//
// 这些用例全部在 run 的 step [1] 返回——LoadObjects / attach / nftables 一个都
// 没走到，所以本测试不需要 root，也不会在被测机器上留下任何内核状态。这就是
// "配置错不动内核状态"这条不变量在单元测试层面的可验证形式。
func TestRunConfigErrorsAreConfigErrors(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "malformed toml", body: "[keys\npsk = 1\n"},
		{name: "psk without prefix", body: "[keys]\npsk = \"deadbeef\"\n" + ifaceBlock},
		{name: "psk truncated", body: "[keys]\npsk = \"hex:0011\"\n" + ifaceBlock},
		{
			name: "bad duration",
			body: "[keys]\npsk = \"" + validPSK + "\"\n" + ifaceBlock + "[policy]\nmax_ttl = \"5minutes\"\n",
		},
		{
			name: "multi-address admin prefix",
			body: "[keys]\npsk = \"" + validPSK + "\"\n" + ifaceBlock + "[safety]\nadmin_allow = [\"10.0.0.0/8\"]\n",
		},
		{name: "interfaces mode auto", body: "[keys]\npsk = \"" + validPSK + "\"\n[interfaces]\nmode = \"auto\"\n"},
		{
			name: "unknown interface",
			body: "[keys]\npsk = \"" + validPSK + "\"\n[interfaces]\nmode = \"explicit\"\nexplicit = [\"knok-no-such-if0\"]\n",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := run(writeCfg(t, tc.body), "")
			if err == nil {
				t.Fatal("run accepted an invalid config")
			}
			var cerr *configError
			if !errors.As(err, &cerr) {
				t.Errorf("run() = %v (%T), want *configError → exit 2", err, err)
			}
		})
	}
}

// TestRunKernelErrorsAreNotConfigErrors 是上一条的补集：step [2] 之后的失败必须
// 落到 exit 3。pin 目录不在 bpffs 上是一个确定性的环境错误（例如配置把 dir 写成了
// /var/lib/knok）——用户改配置能绕过它，但根因是环境不满足，退出码必须区分开，
// 否则自动化会把"内核/权限问题"当成"配置笔误"无限重启。
func TestRunKernelErrorsAreNotConfigErrors(t *testing.T) {
	body := "[keys]\npsk = \"" + validPSK + "\"\n" + ifaceBlock +
		"[pin]\ndir = " + strconv.Quote(filepath.Join(t.TempDir(), "not-bpffs")) + "\n"
	err := run(writeCfg(t, body), "")
	if err == nil {
		t.Fatal("run succeeded with a pin dir outside bpffs")
	}
	var cerr *configError
	if errors.As(err, &cerr) {
		t.Errorf("run() classified a kernel error as config error: %v (want exit 3)", err)
	}
}

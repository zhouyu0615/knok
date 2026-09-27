//go:build linux

// WriteCfg 的入参校验单测。三个上界必须在**写入 map 之前**拒绝：值一旦写进
// cfg，C 侧只会静默截断或永远匹配不上（见 validateCfg 的注释），而这类问题在
// 内核里表现为"SPA 收不到候选包"，极难回溯到配置。validateCfg 不碰 map，
// 所以不需要 root——服务器上 `go test ./...` 即可跑。

package ebpfplat

import "testing"

func TestValidateCfg(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		spaPort, minLen, maxLen uint32
		wantErr                 bool
	}{
		{"knokd 的典型取值", 4242, 65, MaxSPAPkt, false},
		{"spa_port 上界 65535", 65535, 65, MaxSPAPkt, false},
		{"spa_port 为 0（u16 比较永远不等）", 0, 65, MaxSPAPkt, true},
		{"spa_port 超出 u16", 65536, 65, MaxSPAPkt, true},
		{"max_len 恰好 MaxSPAPkt", 4242, MaxSPAPkt, MaxSPAPkt, false},
		{"max_len 超过 MaxSPAPkt（会被 C 侧截断）", 4242, 65, MaxSPAPkt + 1, true},
		{"min_len == max_len", 4242, 100, 100, false},
		{"min_len > max_len（没有包能通过）", 4242, 200, 100, true},
	} {
		err := validateCfg(tc.spaPort, tc.minLen, tc.maxLen)
		if tc.wantErr && err == nil {
			t.Errorf("%s: validateCfg(%d,%d,%d) = nil, want error",
				tc.name, tc.spaPort, tc.minLen, tc.maxLen)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("%s: validateCfg(%d,%d,%d) = %v, want nil",
				tc.name, tc.spaPort, tc.minLen, tc.maxLen, err)
		}
	}
}

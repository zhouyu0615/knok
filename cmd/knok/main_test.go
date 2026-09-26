package main

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/zhouyu0615/knok/pkg/protocol"
)

var testPSK = [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
	17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}

// 64 个十六进制字符的合法 PSK 体，以及对应的期望字节。
const validPSKHex = "0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9"

func wantPSK(t *testing.T) [32]byte {
	t.Helper()
	var k [32]byte
	for i := 0; i < 32; i++ {
		var hi, lo byte
		hi = unhex(t, validPSKHex[i*2])
		lo = unhex(t, validPSKHex[i*2+1])
		k[i] = hi<<4 | lo
	}
	return k
}

func unhex(t *testing.T, c byte) byte {
	t.Helper()
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		t.Fatalf("bad hex char %q in test fixture", c)
		return 0
	}
}

func TestParsePSK(t *testing.T) {
	want := wantPSK(t)
	zero := [32]byte{}
	tests := []struct {
		name    string
		in      string
		want    [32]byte
		wantErr bool
	}{
		{name: "valid hex prefix", in: "hex:" + validPSKHex, want: want},
		{name: "valid uppercase body", in: "hex:" + strings.ToUpper(validPSKHex), want: want},
		{name: "missing hex prefix", in: validPSKHex, want: zero, wantErr: true},
		{name: "uppercase prefix", in: "HEX:" + validPSKHex, want: zero, wantErr: true},
		{name: "empty body", in: "hex:", want: zero, wantErr: true},
		{name: "too short", in: "hex:" + validPSKHex[:62], want: zero, wantErr: true},
		{name: "too long", in: "hex:" + validPSKHex + "ab", want: zero, wantErr: true},
		{name: "non-hex body", in: "hex:" + strings.Repeat("zz", 32), want: zero, wantErr: true},
		{name: "empty string", in: "", want: zero, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parsePSK(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parsePSK(%q) = %x, want error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parsePSK(%q) unexpected error: %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("parsePSK(%q) = %x, want %x", tc.in, got, tc.want)
			}
		})
	}
}

func TestParsePorts(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    []uint16
		wantErr bool
	}{
		{name: "single port", in: "22", want: []uint16{22}},
		{name: "two ports", in: "22,8080", want: []uint16{22, 8080}},
		{name: "whitespace variants", in: " 22 , 8080 ", want: []uint16{22, 8080}},
		{name: "max port", in: "65535", want: []uint16{65535}},
		{name: "empty", in: "", wantErr: true},
		{name: "only whitespace", in: "   ", wantErr: true},
		{name: "trailing comma", in: "22,", wantErr: true},
		{name: "zero", in: "0", wantErr: true},
		{name: "out of range", in: "65536", wantErr: true},
		{name: "negative", in: "-1", wantErr: true},
		{name: "non numeric", in: "abc", wantErr: true},
		{name: "float", in: "22.5", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parsePorts(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parsePorts(%q) = %v, want error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parsePorts(%q) unexpected error: %v", tc.in, err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("parsePorts(%q) = %v, want %v", tc.in, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("parsePorts(%q) = %v, want %v", tc.in, got, tc.want)
				}
			}
		})
	}
}

func TestBuildMessage(t *testing.T) {
	now := time.Unix(1758900000, 0)
	ports := []uint16{22, 8080}
	m, err := buildMessage(ports, 60*time.Second, now)
	if err != nil {
		t.Fatalf("buildMessage: %v", err)
	}
	if m.TS != uint64(now.Unix()) {
		t.Fatalf("TS = %d, want %d", m.TS, now.Unix())
	}
	if m.TTL != 60 {
		t.Fatalf("TTL = %d, want 60", m.TTL)
	}
	if len(m.Ports) != len(ports) || m.Ports[0] != 22 || m.Ports[1] != 8080 {
		t.Fatalf("Ports = %v, want %v", m.Ports, ports)
	}
	var zero [16]byte
	if m.Nonce == zero {
		t.Fatal("Nonce must be randomly generated, got all zeros")
	}

	m2, err := buildMessage(ports, 60*time.Second, now)
	if err != nil {
		t.Fatalf("buildMessage: %v", err)
	}
	if m2.Nonce == m.Nonce {
		t.Fatal("each message needs a fresh nonce")
	}
}

func TestBuildMessageErrors(t *testing.T) {
	now := time.Unix(1758900000, 0)
	tests := []struct {
		name    string
		ports   []uint16
		ttl     time.Duration
		wantErr bool
	}{
		{name: "no ports", ports: nil, ttl: 60 * time.Second, wantErr: true},
		{name: "too many ports", ports: []uint16{1, 2, 3, 4, 5, 6, 7, 8, 9}, ttl: 60 * time.Second, wantErr: true},
		{name: "zero ttl", ports: []uint16{22}, ttl: 0, wantErr: true},
		{name: "sub-second ttl", ports: []uint16{22}, ttl: 500 * time.Millisecond, wantErr: true},
		{name: "negative ttl", ports: []uint16{22}, ttl: -time.Second, wantErr: true},
		{
			name:    "ttl overflow",
			ports:   []uint16{22},
			ttl:     time.Duration(math.MaxUint32)*time.Second + time.Second,
			wantErr: true,
		},
		{name: "one second ttl ok", ports: []uint16{22}, ttl: time.Second},
		{name: "max ports ok", ports: []uint16{1, 2, 3, 4, 5, 6, 7, 8}, ttl: 60 * time.Second},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, err := buildMessage(tc.ports, tc.ttl, now)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("buildMessage(%v, %s) = %+v, want error", tc.ports, tc.ttl, m)
				}
				return
			}
			if err != nil {
				t.Fatalf("buildMessage(%v, %s) unexpected error: %v", tc.ports, tc.ttl, err)
			}
			if m.TTL != uint32(tc.ttl.Seconds()) {
				t.Fatalf("TTL = %d, want %d", m.TTL, uint32(tc.ttl.Seconds()))
			}
		})
	}
}

// buildMessage 的产物必须能真正被线协议编码/解码。
func TestBuildMessageIsEncodable(t *testing.T) {
	m, err := buildMessage([]uint16{22, 8080}, 120*time.Second, time.Unix(1758900000, 0))
	if err != nil {
		t.Fatalf("buildMessage: %v", err)
	}
	pkt, err := protocol.EncodePSK(m, testPSK)
	if err != nil {
		t.Fatalf("EncodePSK: %v", err)
	}
	got, err := protocol.DecodePSK(pkt, testPSK)
	if err != nil {
		t.Fatalf("DecodePSK: %v", err)
	}
	if got.TS != m.TS || got.TTL != m.TTL || got.Nonce != m.Nonce ||
		len(got.Ports) != 2 || got.Ports[0] != 22 || got.Ports[1] != 8080 {
		t.Fatalf("round trip mismatch: got %+v, want %+v", got, m)
	}
}

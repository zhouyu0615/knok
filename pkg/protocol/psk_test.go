package protocol_test

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/zhouyu0615/knok/pkg/protocol"
)

var testPSK = [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
	17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}

func sampleMsg() protocol.Message {
	var n [16]byte
	rand.Read(n[:])
	return protocol.Message{TS: 1758900000, Nonce: n, Ports: []uint16{22}, TTL: 60}
}

func TestPSKRoundTrip(t *testing.T) {
	m := sampleMsg()
	pkt, err := protocol.EncodePSK(m, testPSK)
	if err != nil {
		t.Fatal(err)
	}
	if string(pkt[:4]) != protocol.Magic {
		t.Fatalf("magic mismatch: %q", pkt[:4])
	}
	if len(pkt) > protocol.MaxPktLen {
		t.Fatalf("packet too long: %d", len(pkt))
	}
	got, err := protocol.DecodePSK(pkt, testPSK)
	if err != nil {
		t.Fatal(err)
	}
	if got.TS != m.TS || got.TTL != m.TTL || !bytes.Equal(got.Nonce[:], m.Nonce[:]) ||
		len(got.Ports) != 1 || got.Ports[0] != 22 {
		t.Fatalf("roundtrip mismatch: %+v vs %+v", got, m)
	}
}

func TestPSKWrongKey(t *testing.T) {
	pkt, _ := protocol.EncodePSK(sampleMsg(), testPSK)
	var other [32]byte
	if _, err := protocol.DecodePSK(pkt, other); err != protocol.ErrAuth {
		t.Fatalf("expected ErrAuth, got %v", err)
	}
}

func TestPSKTamper(t *testing.T) {
	pkt, _ := protocol.EncodePSK(sampleMsg(), testPSK)
	pkt[len(pkt)-1] ^= 0xff // 翻转密文/标签最后一位
	if _, err := protocol.DecodePSK(pkt, testPSK); err != protocol.ErrAuth {
		t.Fatalf("expected ErrAuth on tamper, got %v", err)
	}
}

func TestPSKBadMagicAndLength(t *testing.T) {
	if _, err := protocol.DecodePSK([]byte("XXXX"), testPSK); err != protocol.ErrTooShort {
		t.Fatalf("expected ErrTooShort, got %v", err)
	}
	big := make([]byte, protocol.MaxPktLen+1)
	copy(big, protocol.Magic)
	if _, err := protocol.DecodePSK(big, testPSK); err != protocol.ErrTooLong {
		t.Fatalf("expected ErrTooLong, got %v", err)
	}
	pkt, _ := protocol.EncodePSK(sampleMsg(), testPSK)
	pkt[0] = 'X'
	if _, err := protocol.DecodePSK(pkt, testPSK); err != protocol.ErrBadMagic {
		t.Fatalf("expected ErrBadMagic, got %v", err)
	}
}

// 测试向量固化：首次运行生成，之后校验一致性（M3 协议演进时对照）。
func TestPSKVectors(t *testing.T) {
	path := filepath.Join("testdata", "vectors.json")
	type vec struct {
		PSKHex   string   `json:"psk_hex"`
		PktHex   string   `json:"pkt_hex"`
		TS       uint64   `json:"ts"`
		TTL      uint32   `json:"ttl"`
		Ports    []uint16 `json:"ports"`
		NonceHex string   `json:"nonce_hex"`
	}
	// 固定输入（不随机），保证向量可复现
	fixedNonce := [16]byte{0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
		0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0}
	m := protocol.Message{TS: 1758900000, Nonce: fixedNonce, Ports: []uint16{22, 8080}, TTL: 120}
	// EncodePSK 内部随机生成 AEAD nonce；向量化需要可注入——用 EncodePSKWithNonce
	pkt, err := protocol.EncodePSKWithNonce(m, testPSK, [24]byte{7})
	if err != nil {
		t.Fatal(err)
	}
	v := vec{PSKHex: hexOf(testPSK[:]), PktHex: hexString(pkt), TS: m.TS, TTL: m.TTL,
		Ports: m.Ports, NonceHex: hexString(fixedNonce[:])}
	if os.Getenv("UPDATE_VECTORS") == "1" {
		os.MkdirAll(filepath.Dir(path), 0o755)
		b, _ := json.MarshalIndent([]vec{v}, "", "  ")
		os.WriteFile(path, b, 0o644)
		t.Skip("vectors updated")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("testdata/vectors.json missing; run UPDATE_VECTORS=1 go test ./pkg/protocol -run Vectors")
	}
	var saved []vec
	json.Unmarshal(b, &saved)
	if len(saved) != 1 || saved[0].PktHex != v.PktHex {
		t.Fatalf("vector mismatch: encoding changed!\n got %s\nwant %s", v.PktHex, saved[0].PktHex)
	}
}

func hexOf(b []byte) string { return hexString(b) }
func hexString(b []byte) string {
	const d = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2], out[i*2+1] = d[c>>4], d[c&0xf]
	}
	return string(out)
}

// Package protocol 实现 knok SPA 线协议。
//
// DEPRECATED(M2): 本文件是 PSK 临时简化实现，M3 将替换为
// X25519 + Ed25519 完整 v1 协议（见 spec §3）。禁止在生产使用 PSK 模式。
package protocol

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	Magic   = "KNOK"
	Version = 1
	// FlagPSK 标记 M2 预共享密钥模式。v1 正式协议将清除该 flag 语义。
	FlagPSK = 0x80

	aeadNonceSize = 24 // XChaCha20-Poly1305
	MaxPorts      = 8
	MaxPktLen     = 512
	// 头 6B + aeadNonce 24B + tag 16B + 内层最小 8+16+1+2+4=31B
	MinPSKPktLen = 6 + aeadNonceSize + 16 + 31
)

var (
	ErrTooShort   = errors.New("protocol: packet too short")
	ErrTooLong    = errors.New("protocol: packet too long")
	ErrBadMagic   = errors.New("protocol: bad magic")
	ErrBadVersion = errors.New("protocol: unsupported version or mode")
	ErrAuth       = errors.New("protocol: authentication failed")
	ErrBadMsg     = errors.New("protocol: malformed inner message")
)

// Message 是 SPA 包内层明文。
type Message struct {
	TS    uint64 // unix 秒
	Nonce [16]byte
	Ports []uint16
	TTL   uint32 // 秒
}

// EncodePSK 生成随机 AEAD nonce 并编码。
func EncodePSK(m Message, psk [32]byte) ([]byte, error) {
	var n [24]byte
	if _, err := rand.Read(n[:]); err != nil {
		return nil, fmt.Errorf("protocol: rand: %w", err)
	}
	return EncodePSKWithNonce(m, psk, n)
}

// EncodePSKWithNonce 使用指定 AEAD nonce（测试向量需要确定性输出）。
func EncodePSKWithNonce(m Message, psk [32]byte, aeadNonce [24]byte) ([]byte, error) {
	if len(m.Ports) == 0 || len(m.Ports) > MaxPorts {
		return nil, fmt.Errorf("%w: ports count %d", ErrBadMsg, len(m.Ports))
	}
	if m.TTL == 0 {
		return nil, fmt.Errorf("%w: zero ttl", ErrBadMsg)
	}
	inner := make([]byte, 8+16+1+len(m.Ports)*2+4)
	binary.BigEndian.PutUint64(inner[0:8], m.TS)
	copy(inner[8:24], m.Nonce[:])
	inner[24] = byte(len(m.Ports))
	for i, p := range m.Ports {
		binary.BigEndian.PutUint16(inner[25+i*2:], p)
	}
	binary.BigEndian.PutUint32(inner[25+len(m.Ports)*2:], m.TTL)

	aead, err := chacha20poly1305.NewX(psk[:])
	if err != nil {
		return nil, err
	}
	hdr := make([]byte, 0, 6+aeadNonceSize)
	hdr = append(hdr, Magic...)
	hdr = append(hdr, Version, FlagPSK)
	hdr = append(hdr, aeadNonce[:]...)
	ct := aead.Seal(nil, aeadNonce[:], inner, hdr) // AAD 绑定头部
	out := append(hdr, ct...)
	if len(out) > MaxPktLen {
		return nil, ErrTooLong
	}
	return out, nil
}

// DecodePSK 校验并解码 SPA 包。所有失败路径返回哨兵错误。
func DecodePSK(pkt []byte, psk [32]byte) (Message, error) {
	if len(pkt) < MinPSKPktLen {
		return Message{}, ErrTooShort
	}
	if len(pkt) > MaxPktLen {
		return Message{}, ErrTooLong
	}
	if string(pkt[0:4]) != Magic {
		return Message{}, ErrBadMagic
	}
	if pkt[4] != Version || pkt[5]&FlagPSK == 0 {
		return Message{}, ErrBadVersion
	}
	aeadNonce := pkt[6 : 6+aeadNonceSize]
	hdr := pkt[:6+aeadNonceSize]

	aead, err := chacha20poly1305.NewX(psk[:])
	if err != nil {
		return Message{}, err
	}
	inner, err := aead.Open(nil, aeadNonce, pkt[6+aeadNonceSize:], hdr)
	if err != nil {
		return Message{}, ErrAuth
	}
	if len(inner) < 8+16+1+2+4 {
		return Message{}, ErrBadMsg
	}
	var m Message
	m.TS = binary.BigEndian.Uint64(inner[0:8])
	copy(m.Nonce[:], inner[8:24])
	n := int(inner[24])
	if n == 0 || n > MaxPorts || len(inner) != 25+n*2+4 {
		return Message{}, ErrBadMsg
	}
	m.Ports = make([]uint16, 0, n)
	for i := 0; i < n; i++ {
		m.Ports = append(m.Ports, binary.BigEndian.Uint16(inner[25+i*2:]))
	}
	m.TTL = binary.BigEndian.Uint32(inner[25+n*2:])
	return m, nil
}

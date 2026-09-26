// Command knok 是 M2 最小客户端：只支持 PSK 模式，仅供开发联调。
// 生产协议（X25519 + Ed25519）在 M3 落地，见 spec §3。
package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"math"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/zhouyu0615/knok/pkg/protocol"
)

// versionLine 必须一眼看出当前是开发用的 PSK 模式。
const versionLine = "knok M2 (PSK mode - development only)"

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "keygen":
		cmdKeygen(os.Args[2:])
	case "auth":
		cmdAuth(os.Args[2:])
	case "version":
		fmt.Println(versionLine)
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `knok - one packet, signed, the door opens

commands:
  keygen --psk                 generate a pre-shared key (M2 development mode)
  auth --server <ip> [flags]   send an SPA knock

auth flags:
  --spa-port 4242   --ports 22 (comma-separated)   --ttl 60s
  --psk hex:<64>    --exec "ssh user@host"`)
	os.Exit(2)
}

func cmdKeygen(args []string) {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	pskMode := fs.Bool("psk", false, "generate 32-byte PSK")
	fs.Parse(args)
	if !*pskMode {
		fmt.Fprintln(os.Stderr, "M2 only supports --psk; Ed25519 keys arrive in M3")
		os.Exit(2)
	}
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("hex:%s\n", hex.EncodeToString(k[:]))
}

func cmdAuth(args []string) {
	fs := flag.NewFlagSet("auth", flag.ExitOnError)
	server := fs.String("server", "", "server IP or hostname")
	spaPort := fs.Uint("spa-port", 4242, "SPA UDP port")
	portsStr := fs.String("ports", "22", "comma-separated ports to authorize")
	ttl := fs.Duration("ttl", 60*time.Second, "authorization TTL")
	pskFlag := fs.String("psk", "", "hex:<64 hex chars>")
	execCmd := fs.String("exec", "", "command to run after knock")
	fs.Parse(args)

	if *server == "" || *pskFlag == "" {
		fs.Usage()
		os.Exit(2)
	}
	psk, err := parsePSK(*pskFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	ports, err := parsePorts(*portsStr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	addr := net.JoinHostPort(*server, strconv.Itoa(int(*spaPort)))
	conn, err := net.Dial("udp", addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer conn.Close()

	// 3 次重试，每次全新 nonce/ts，指数退避
	backoff := []time.Duration{0, 200 * time.Millisecond, 800 * time.Millisecond}
	sent := false
	for i, wait := range backoff {
		if wait > 0 {
			time.Sleep(wait)
		}
		msg, err := buildMessage(ports, *ttl, time.Now())
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		pkt, err := protocol.EncodePSK(msg, psk)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if _, err := conn.Write(pkt); err != nil {
			fmt.Fprintf(os.Stderr, "attempt %d: %v\n", i+1, err)
			continue
		}
		fmt.Fprintf(os.Stderr, "knock sent to %s (attempt %d, ports %v, ttl %s)\n",
			addr, i+1, ports, *ttl)
		sent = true
		break // UDP 无确认；发送成功即结束重试
	}
	if !sent {
		fmt.Fprintf(os.Stderr, "knock failed: could not send to %s\n", addr)
		os.Exit(1)
	}

	if *execCmd != "" {
		time.Sleep(300 * time.Millisecond) // 等待服务端完成验证与打标
		cmd := exec.Command("sh", "-c", *execCmd)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "exec failed (authorization may not have landed): %v\n", err)
			os.Exit(1)
		}
	}
}

// parsePSK 解析 --psk 的 `hex:<64 hex chars>` 形式，与 knokd 配置使用同一格式。
func parsePSK(s string) ([32]byte, error) {
	var k [32]byte
	body, ok := strings.CutPrefix(s, "hex:")
	if !ok {
		return k, fmt.Errorf("--psk must be hex:<64 hex chars>")
	}
	b, err := hex.DecodeString(body)
	if err != nil || len(b) != 32 {
		return k, fmt.Errorf("--psk invalid")
	}
	copy(k[:], b)
	return k, nil
}

// parsePorts 解析逗号分隔的端口列表，允许空格，元素须落在 1..65535。
func parsePorts(s string) ([]uint16, error) {
	var ports []uint16
	for _, part := range strings.Split(s, ",") {
		p, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil || p < 1 || p > 65535 {
			return nil, fmt.Errorf("bad port %q", part)
		}
		ports = append(ports, uint16(p))
	}
	if len(ports) == 0 {
		return nil, fmt.Errorf("no ports given")
	}
	return ports, nil
}

// buildMessage 用给定时刻与全新 nonce 组装内层消息；ttl 需为 1s..2^32-1s。
func buildMessage(ports []uint16, ttl time.Duration, now time.Time) (protocol.Message, error) {
	if len(ports) == 0 || len(ports) > protocol.MaxPorts {
		return protocol.Message{}, fmt.Errorf("need 1-%d ports, got %d", protocol.MaxPorts, len(ports))
	}
	secs := ttl / time.Second
	if secs < 1 || secs > time.Duration(math.MaxUint32) {
		return protocol.Message{}, fmt.Errorf("--ttl must be between 1s and %ds, got %s",
			uint64(math.MaxUint32), ttl)
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return protocol.Message{}, fmt.Errorf("nonce: %w", err)
	}
	return protocol.Message{
		TS:    uint64(now.Unix()),
		Nonce: nonce,
		Ports: ports,
		TTL:   uint32(secs),
	}, nil
}

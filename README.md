# knok

> Knock knock. One packet, signed. The door opens.

**knok** is a modern Single Packet Authorization (SPA) implementation built with **eBPF + Go** — a ground-up rethinking of [fwknop](https://github.com/mrash/fwknop) for the cloud-native era.

Your server keeps a default-drop firewall with **zero open ports**. To get in, the client sends a single encrypted, signed, replay-proof UDP packet. knok verifies it in microseconds and opens the door for a limited time. Scanners see nothing. Nmap sees nothing. Nobody gets in without the key.

## How it works

```
knok client (any OS)                     knokd (Linux)
     │                                        │
     │  one UDP packet:                       │  TC/TCX eBPF program
     │  XChaCha20-Poly1305 + Ed25519 sig      │   ├─ allowlist map lookup → mark & accept
     ├───────────────────────────────────────►│   ├─ cheap magic-byte filter for junk
     │                                        │   └─ SPA candidates → ringbuf → Go daemon
     │                                        │  verify → write allowlist (in-kernel TTL)
```

- **Data plane in kernel**: authorization state lives in eBPF maps with in-kernel expiry — no `fork/exec iptables`, no userspace rule scanning.
- **Control plane in Go**: concurrent packet verification, structured audit events, Prometheus metrics.
- **Firewall-friendly**: packets are marked and handed to nftables for the accept decision — NAT, conntrack and logging all keep working.

## vs. fwknop

| | fwknop | knok |
|---|---|---|
| Authorization path | fork/exec iptables (ms) | eBPF map write (µs) |
| Packet capture | libpcap polling | TC/XDP + ringbuf (event-driven) |
| Concurrency | single-threaded C | Go goroutine pool |
| Crypto | Rijndael-CBC / GnuPG (+HMAC) | XChaCha20-Poly1305 AEAD + Ed25519 |
| Rate limiting / audit / metrics | — | built in |

## Status

🚧 **Early development — M2 milestone reached.** The end-to-end knock flow works
over UDP on Linux (TCX/TC + nftables): `knok auth` opens the hidden port for a
bounded TTL and the grant survives a daemon restart. `scripts/e2e.sh`
(`make e2e`) verifies exactly that against a live kernel. The production crypto
handshake (Ed25519 + X25519) lands in M3. Nothing here is production-ready yet.

Planned layout:

```
cmd/knok/       client CLI (cross-platform, pure Go)
cmd/knokd/      server daemon (Linux, cilium/ebpf)
pkg/protocol/   packet format, AEAD, signatures (the executable spec)
bpf/            eBPF sources (bpf2go)
```

## Requirements (server side)

- Linux kernel ≥ 5.8 (TC + ringbuf); ≥ 6.6 uses TCX automatically
- nftables for the accept rule (installed by `knokd`)

## License

GPL-2.0 — same lineage as fwknop. See [LICENSE](LICENSE).

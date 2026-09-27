# knok

> Knock knock. One packet, signed. The door opens.

**knok** is a modern Single Packet Authorization (SPA) implementation built with **eBPF + Go** — a ground-up rethinking of [fwknop](https://github.com/mrash/fwknop) for the cloud-native era.

Your server keeps a default-drop firewall with **zero open ports**. To get in, the client sends a single encrypted, replay-proof UDP packet. knok verifies it in microseconds and opens the door for a limited time. Scanners see nothing. Nmap sees nothing. Nobody gets in without the key.

## How it works (M2)

```
knok client (any OS)                     knokd (Linux)
     │                                        │
     │  one UDP packet:                       │  TC/TCX eBPF program
     │  XChaCha20-Poly1305, PSK mode          │   ├─ allowlist map lookup → mark & accept
     ├───────────────────────────────────────►│   ├─ magic-byte filter for junk
     │                                        │   └─ SPA candidates → ringbuf → Go daemon
     │                                        │  verify (PSK AEAD) → write allowlist (in-kernel TTL)
     │                                        │  nftables `inet knok`: unmarked → drop
```

**M2 is the thin end-to-end slice, and this README describes M2, not the target design.**
Today: one UDP transport, PSK-mode AEAD (no Ed25519 signature, no X25519 key
agreement), **one** authenticator goroutine, **no rate limiting**
(`StRateDrop` is a reserved slot the dataplane never bumps), interface discovery
only in `explicit` mode. The full v1 handshake and the rest of the spec arrive in
M3–M6.

- **Data plane in kernel**: authorization state lives in eBPF maps with in-kernel expiry — no `fork/exec iptables`, no userspace rule scanning.
- **Control plane in Go**: structured audit events (JSON to stdout) and a Prometheus `/metrics` endpoint. Verification itself is a single goroutine in M2.
- **Firewall-friendly**: packets are marked and handed to nftables for the accept decision — NAT, conntrack and logging all keep working.

## vs. fwknop

| | fwknop | knok (M2) |
|---|---|---|
| Authorization path | fork/exec iptables (ms) | eBPF map write (µs) |
| Packet capture | libpcap polling | TC/TCX + ringbuf (event-driven) |
| Concurrency | single-threaded C | single Go goroutine (pool later) |
| Crypto | Rijndael-CBC / GnuPG (+HMAC) | XChaCha20-Poly1305 over a PSK; Ed25519/X25519 in M3 |
| Rate limiting | — | not yet (reserved slot; M6) |
| Audit / metrics | — | structured JSON audit + `/metrics` |

## Quickstart (server)

Requires Linux ≥ 5.8, root, `nft`, and bpffs mounted at `/sys/fs/bpf`.

```sh
go build -o knokd ./cmd/knokd     # the repository ships no `make build` target
go build -o knok ./cmd/knok
./knok keygen --psk               # prints "hex:<64 hex chars>" — M2 development mode only
sudo ./knokd -config /etc/knok/knokd.toml
```

`/etc/knok/knokd.toml` — the file is the **only** configuration source (the CLI
has just `-config`, `-uninstall`, `-metrics`):

```toml
[keys]
psk = "hex:..."                  # the value printed by `knok keygen --psk`

[listen]
spa_udp_port = 4242
protected_ports = [22]

[policy]
allowed_ports = [22]             # must cover every protected port, or it can never be granted
max_ttl = "30m"
ts_window = "300s"

[safety]
admin_allow = ["203.0.113.7/32"] # escape hatch: permanent grant, no knock

[interfaces]
mode = "explicit"                # M2 supports ONLY "explicit" (the spec's "auto" example does not start M2)
explicit = ["eth0"]

[pin]
dir = "/sys/fs/bpf/knok"
```

Then knock from the client:

```sh
./knok auth --server 203.0.113.10 --spa-port 4242 --ports 22 --ttl 60s --psk "hex:..."
```

A grant is **protocol-agnostic** today: authorizing port 22 opens it for both TCP
and UDP (the dataplane marks both, and nftables drops both when unmarked). The
SPA transport itself is UDP-only in M2.

## The `inet knok` nftables contract (operator-facing)

knokd installs drop rules for the protected ports in a table it owns. **Your own
firewall rules and other tooling must respect that table:**

- **knok owns the `inet knok` table.** It is replaced wholesale on start-up
  (`add table` + `flush table`); do not add your own rules to it.
- The table hooks `input` at **priority -200** (before your `filter` chain).
- The mark **`0x4b4e4f4b`** (ASCII "KNOK") is **reserved for knok**. Do not use it
  for your own packets and do not write rules that depend on it.
- **Do not write accept rules for protected ports in your own firewall.** The
  contract is "no mark → drop, mark → accept"; a second accept rule for a
  protected port creates two competing semantics for the same packet.
- There is **no automatic conflict detection yet**: knokd does not inspect your
  chains at start-up, and it warns only about its own configuration (a protected
  port that is missing from `policy.allowed_ports` locks that port for everyone).
  Keep `safety.admin_allow` (and a cloud console) as your way back in.

`knokd` keeps the table on shutdown (fail-closed: authorized traffic and the
default-drop decision outlive the daemon). `knokd -uninstall` removes the table,
the attachments and the pinned state.

## Known limitations (M2)

- **The replay cache is in-memory.** A captured knock can be replayed after a
  daemon restart as long as it is inside `ts_window` (default 300 s): the nonce
  record is gone, the timestamp is still valid, and because grants are written
  for the **source IP** of the packet, the replayer's address gets the grant
  (source-IP rebinding) for the requested TTL. Exposure = an attacker who can
  capture and replay a knock, plus a restart inside that window. M3 moves the
  cache to a pinned/persisted store so restarts stop losing replay records.
- **PSK mode only** — no Ed25519 signature and no X25519 key agreement yet; the
  PSK is a development-mode simplification, not the production handshake.
- **No rate limiting** — `StRateDrop` is a reserved no-op slot (M6).
- **`interfaces.mode` only supports `explicit`** — `auto`/`exclude` are not
  implemented (M5).
- **`admin_allow` accepts single addresses only** (`/32`, `/128`).

## Status

🚧 **Early development — M2 milestone reached.** The end-to-end knock flow works
over UDP on Linux (TCX/TC + nftables): `knok auth` opens the hidden port for a
bounded TTL and the grant survives a daemon restart. `scripts/e2e.sh`
(`make e2e`) verifies exactly that against a live kernel. See "Known limitations
(M2)" above for what is deliberately not there yet, and the spec
(`docs/superpowers/specs/2026-09-26-knok-mvp-design.md`) for the target. Nothing
here is production-ready.

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
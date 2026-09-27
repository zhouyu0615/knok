# knok

English | [中文](README.zh-CN.md)

> Knock knock. One packet, signed. The door opens.

**knok** is a modern **Single Packet Authorization (SPA)** implementation in **eBPF + Go** — a ground-up rethink of [fwknop](https://github.com/mrash/fwknop) for the cloud-native era.

## The problem it solves

A server that exposes SSH (or any admin port) to the internet is scanned and brute-forced within minutes, and a 0-day in that service is exploitable by anyone who can reach it. The usual answers all have costs: IP allowlists need fixed client addresses; a VPN means a persistent tunnel, client software and a much larger trusted surface; a reverse tunnel needs a relay.

knok removes the port from the network entirely:

- **Before a knock, the protected port does not exist.** Every packet is dropped silently — no RST, no ICMP, no banner. Nmap reports nothing to exploit because there is nothing to find.
- **One UDP packet opens it, for one source address, for a bounded TTL.** The client sends a single AEAD-encrypted packet containing a timestamp, a random nonce and the ports it wants. knok verifies it in the kernel-adjacent fast path and grants the **source IP** access for `min(requested TTL, policy max)`.
- **The door closes itself.** Expiry is evaluated in the data path, packet by packet — no cron, no userspace rule scanning, no cleanup job.

| | fwknop | knok (M2) |
|---|---|---|
| Opening the door | `fork/exec iptables` (~ms) | eBPF map write (~µs) |
| Packet capture | libpcap polling | TC/TCX + ringbuf (event-driven) |
| Crypto | Rijndael-CBC / GnuPG (+HMAC) | XChaCha20-Poly1305 (PSK mode in M2; Ed25519/X25519 in M3) |
| Audit / metrics | — | structured JSON audit + `/metrics` |

## How it works

![knok architecture](docs/diagrams/architecture.svg)

The control plane (Go) verifies knocks and writes authorization state into pinned eBPF maps. The data plane (TC/TCX) only looks up that state, marks authorized packets, and filters junk — the accept/drop decision belongs to an nftables table knok owns. That split is why NAT, conntrack and your existing logging keep working. The numbered lines ①–⑥ under the diagram are the data path.

The full knock flow — knock, verification, authorized traffic, TTL expiry:

![knok knock flow](docs/diagrams/knock-flow.svg)

Editable sources: [`docs/diagrams/architecture.drawio`](docs/diagrams/architecture.drawio), [`docs/diagrams/knock-flow.puml`](docs/diagrams/knock-flow.puml), [`docs/diagrams/daemon-startup.puml`](docs/diagrams/daemon-startup.puml).

## Run it (5 steps)

Requires Linux ≥ 5.8 (kernel ≥ 6.6 selects TCX automatically), root, `nft`, and bpffs mounted at `/sys/fs/bpf`.

```sh
# 1. build (both binaries)
go build -o knokd ./cmd/knokd
go build -o knok  ./cmd/knok

# 2. generate the pre-shared key (M2 development mode) — same key on both sides
./knok keygen --psk
#   → hex:1f3c...   (copy this value)

# 3. write the server config
sudo mkdir -p /etc/knok
sudo tee /etc/knok/knokd.toml >/dev/null <<'EOF'
[keys]
psk = "hex:1f3c..."            # paste the value from step 2

[listen]
spa_udp_port = 4242            # where knocks arrive
protected_ports = [22]         # ports to hide

[policy]
allowed_ports = [22]           # must cover every protected port
max_ttl = "30m"
ts_window = "300s"

[safety]
admin_allow = ["203.0.113.7/32"]   # YOUR admin address: permanent access, no knock

[interfaces]
mode = "explicit"
explicit = ["eth0"]            # M2 supports only explicit mode

[pin]
dir = "/sys/fs/bpf/knok"
EOF

# 4. start the daemon (the firewall is installed LAST, only after the
#    authorization path is live — see docs/diagrams/daemon-startup.puml)
sudo ./knokd -config /etc/knok/knokd.toml

# 5. from the client: knock, then connect
./knok auth --server <server-ip> --spa-port 4242 --ports 22 --ttl 60s \
    --psk "hex:1f3c..." --exec "ssh user@<server-ip>"
```

Verify and clean up:

```sh
sudo nft list table inet knok            # the drop rules knok installed
curl -s 127.0.0.1:9601/metrics           # eBPF counters + Go-side ringbuf counters
sudo make e2e                            # full acceptance run against a live kernel
sudo ./knokd -uninstall -config /etc/knok/knokd.toml   # remove table, attachments, pins
```

## Changing the configuration

The config file is the **only** configuration source (the CLI has just `-config`, `-uninstall`, `-metrics`).

| Field | Meaning | Notes / defaults |
|---|---|---|
| `keys.psk` | Pre-shared key, `hex:<64 hex chars>` | must match the client's `--psk`; `knok keygen --psk` prints it |
| `listen.spa_udp_port` | UDP port that receives knocks | default `4242`; also dropped in nftables to stay silent |
| `listen.protected_ports` | Ports to hide (`[22, 2222]`) | rendered as `tcp` **and** `udp` drop rules |
| `policy.allowed_ports` | Ports a knock may ever request | **must cover every protected port**, otherwise that port is unreachable forever; knokd warns if it does not |
| `policy.max_ttl` | Upper bound on any grant | default `30m`; must be > 0 |
| `policy.ts_window` | Accepted clock skew of a knock | default `300s`; also the replay-cache lifetime; must be > 0 |
| `safety.admin_allow` | Permanent grants (escape hatch), no knock | single addresses only (`/32`, `/128`); set this **before** your first start |
| `interfaces.mode` / `interfaces.explicit` | Interfaces to attach to | M2 supports only `explicit` with at least one name |
| `pin.dir` | Where maps/links are pinned | default `/sys/fs/bpf/knok`; must be an absolute path at least two levels deep (a typo here is refused rather than deleted) |

How to apply a change:

1. edit `/etc/knok/knokd.toml`;
2. restart the daemon (`Ctrl-C` then `sudo ./knokd -config ...`). **M2 has no hot reload** — `SIGHUP` arrives in M5. On shutdown the daemon deliberately keeps the eBPF attachments and the nftables table (fail-closed: already-authorized traffic and the default drop survive a crash);
3. the nftables table is replaced wholesale at start-up, so removing a protected port actually unhides it; grants that are still unexpired survive the restart because the maps are pinned;
4. to remove every trace: `sudo ./knokd -uninstall -config /etc/knok/knokd.toml`.

Two rules that keep you out of trouble: keep `safety.admin_allow` (or a cloud console) as your way back in, and **do not add accept rules for protected ports to your own firewall** — the contract is "no mark → drop, mark → accept", and a second accept rule gives the same packet two competing meanings.

### The `inet knok` table knok owns

- knok owns `inet knok` and replaces it wholesale; do not put your own rules in it.
- It hooks `input` at **priority -200**, before your `filter` chain, and keeps `policy accept` — your own rules still apply to traffic that passes.
- The mark **`0x4b4e4f4b`** (ASCII "KNOK") is reserved: do not use it for your own packets.
- There is **no automatic conflict detection yet** — knokd does not inspect your chains, it only warns about its own configuration.

## Known limitations (M2)

- **The replay cache is in-memory.** A captured knock can be replayed after a daemon restart while it is still inside `ts_window`, and because a grant is bound to the packet's **source IP**, the replayer's address gets the grant. M3 moves the cache to a pinned/persisted store.
- **PSK mode only** — no Ed25519 signature, no X25519 key agreement yet.
- **No rate limiting** (`StRateDrop` is a reserved slot, M6), **one** authenticator goroutine, and `interfaces.mode` only supports `explicit` (M5).
- **UDP SPA transport only**; a grant is protocol-agnostic (it opens the port for both TCP and UDP).
- **Not production-ready.** The target design is the spec: [`docs/superpowers/specs/2026-09-26-knok-mvp-design.md`](docs/superpowers/specs/2026-09-26-knok-mvp-design.md).

## Status

🚧 **Early development — v0.1 (M2 milestone reached).** The end-to-end flow works over UDP on Linux (TCX/TC + nftables): a knock opens the hidden port for a bounded TTL, the grant survives a daemon restart, and `scripts/e2e.sh` (`sudo make e2e`) verifies exactly that against a live kernel.

```
cmd/knok/       client CLI (cross-platform, pure Go)
cmd/knokd/      server daemon (Linux, cilium/ebpf)
pkg/protocol/   packet format, AEAD, signatures (the executable spec)
internal/core/  verification pipeline and interfaces (platform-free)
internal/platform/  eBPF, nftables, mark (Linux adapters)
bpf/            eBPF sources (bpf2go)
```

## License

GPL-2.0 — same lineage as fwknop. See [LICENSE](LICENSE).
// SPDX-License-Identifier: GPL-2.0
// knok M2 数据面：allowlist 打标 + UDP SPA 候选上送。TCP SYN 匹配在 M4 加入。
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define TC_ACT_OK 0

#define MARK_KNOK   0x4B4E4F4B
#define MAX_SPA_PKT 512

/* stats 槽位（与 Go 侧 types.go 一致） */
#define ST_TOTAL 0
#define ST_ALLOW_HIT 1
#define ST_ALLOW_EXPIRY 2
#define ST_CANDIDATE 3
#define ST_RATE_DROP 4
#define ST_RINGBUF_DROP 5
#define ST_SLOTS 6

struct allow_key {
    __u8 ip[16]; /* IPv4 以 v4-mapped IPv6 存储 */
    __u16 port;  /* 主机序 */
    __u16 pad;
};

struct cfg_val {
    __u32 spa_port; /* 主机序 */
    __u32 min_len;
    __u32 max_len;
};

struct spa_event {
    __u64 ts_ns;
    __u32 ifindex;
    __u8 ipver;
    __u8 pad[3];
    __u8 src_ip[16];
    __u16 src_port;
    __u16 dst_port;
    __u16 payload_len;
    __u8 payload[MAX_SPA_PKT];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct allow_key);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} allowlist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct cfg_val);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} cfg SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} spa_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, ST_SLOTS);
    __type(key, __u32);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} stats SEC(".maps");

static __always_inline void bump(__u32 slot)
{
    __u64 *v = bpf_map_lookup_elem(&stats, &slot);
    if (v)
        __sync_fetch_and_add(v, 1);
}

SEC("tc")
int knok_ingress(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    bump(ST_TOTAL);

    struct allow_key key = {};
    __u8 ipver;
    void *l4;

    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *iph = (void *)(eth + 1);
        if ((void *)(iph + 1) > data_end)
            return TC_ACT_OK;
        if (iph->ihl < 5)
            return TC_ACT_OK;
        __u32 ihl_len = (__u32)iph->ihl * 4;
        if ((void *)iph + ihl_len > data_end)
            return TC_ACT_OK;
        if (iph->protocol != IPPROTO_UDP)
            return TC_ACT_OK; /* M2: UDP only */
        ipver = 4;
        key.ip[10] = 0xff;
        key.ip[11] = 0xff;
        __builtin_memcpy(&key.ip[12], &iph->saddr, 4);
        l4 = (void *)iph + ihl_len;
    } else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end)
            return TC_ACT_OK;
        if (ip6->nexthdr != IPPROTO_UDP)
            return TC_ACT_OK;
        ipver = 6;
        __builtin_memcpy(key.ip, &ip6->saddr, 16);
        l4 = (void *)(ip6 + 1);
    } else {
        return TC_ACT_OK;
    }

    struct udphdr *udp = l4;
    if ((void *)(udp + 1) > data_end)
        return TC_ACT_OK;
    key.port = bpf_ntohs(udp->dest);

    /* 1) allowlist：命中且未过期 → 打 mark 放行（全程内核内） */
    __u64 *expiry = bpf_map_lookup_elem(&allowlist, &key);
    if (expiry) {
        if (*expiry > bpf_ktime_get_ns()) {
            skb->mark = MARK_KNOK;
            bump(ST_ALLOW_HIT);
            return TC_ACT_OK;
        }
        bpf_map_delete_elem(&allowlist, &key);
        bump(ST_ALLOW_EXPIRY);
    }

    /* 2) SPA 候选：目标端口 == cfg.spa_port 且载荷前 4 字节 == "KNOK" */
    __u32 zero = 0;
    struct cfg_val *c = bpf_map_lookup_elem(&cfg, &zero);
    if (!c || key.port != c->spa_port)
        return TC_ACT_OK;

    __u32 hdr_len = (__u32)((void *)(udp + 1) - data);
    __u32 pkt_len = (__u32)(data_end - data);
    if (pkt_len < hdr_len + 4)
        return TC_ACT_OK;
    __u32 plen = pkt_len - hdr_len;

    __u8 magic[4];
    if (bpf_skb_load_bytes(skb, hdr_len, magic, sizeof(magic)) < 0)
        return TC_ACT_OK;
    if (magic[0] != 'K' || magic[1] != 'N' || magic[2] != 'O' || magic[3] != 'K')
        return TC_ACT_OK;
    if (plen < c->min_len || plen > c->max_len)
        return TC_ACT_OK;

    __u32 copy_len = plen;
    if (copy_len > MAX_SPA_PKT)
        copy_len = MAX_SPA_PKT;

    struct spa_event *e = bpf_ringbuf_reserve(&spa_events, sizeof(*e), 0);
    if (!e) {
        bump(ST_RINGBUF_DROP);
        return TC_ACT_OK;
    }
    e->ts_ns = bpf_ktime_get_ns();
    e->ifindex = skb->ifindex;
    e->ipver = ipver;
    e->pad[0] = 0; e->pad[1] = 0; e->pad[2] = 0;
    __builtin_memcpy(e->src_ip, key.ip, 16);
    e->src_port = bpf_ntohs(udp->source);
    e->dst_port = key.port;
    e->payload_len = (__u16)copy_len;
    __builtin_memset(e->payload, 0, MAX_SPA_PKT);
    if (bpf_skb_load_bytes(skb, hdr_len, e->payload, copy_len) < 0) {
        bpf_ringbuf_discard(e, 0);
        return TC_ACT_OK;
    }
    bump(ST_CANDIDATE);
    bpf_ringbuf_submit(e, 0);
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";

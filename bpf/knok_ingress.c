// SPDX-License-Identifier: GPL-2.0
// knok M2 数据面：allowlist 打标（UDP 与 TCP 一致）+ UDP SPA 候选上送。
// TCP SYN 匹配在 M4 加入——M2 的 TCP 只被 allowlist 打标，不做候选匹配。
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define TC_ACT_OK 0

/* EtherType 常量：老内核的 vmlinux.h 只导出使用中的枚举成员，ETH_P_IP/ETH_P_IPV6
 * 不在其中（bpftool 只 dump BTF 里存在的符号）。不能改用 <linux/if_ether.h>（会与
 * vmlinux.h 的类型定义冲突），故按 IEEE 802 的标准值本地定义。语义与内核 uapi 一致。 */
#define ETH_P_IP   0x0800
#define ETH_P_IPV6 0x86DD

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
    /* M2 的 L4 范围是 UDP 与 TCP：两者都要走 allowlist 打标——受保护的业务端口
     * 多为 TCP（SSH 就是），拿不到 mark 的 TCP 会被 nftables 的 drop 规则拦掉。
     * 其它 L4 协议（ICMP 等）原样放行，不参与任何判定。 */
    __u8 is_udp = 0;
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
        if (iph->protocol != IPPROTO_UDP && iph->protocol != IPPROTO_TCP)
            return TC_ACT_OK; /* M2: UDP + TCP only */
        is_udp = iph->protocol == IPPROTO_UDP;
        ipver = 4;
        key.ip[10] = 0xff;
        key.ip[11] = 0xff;
        __builtin_memcpy(&key.ip[12], &iph->saddr, 4);
        l4 = (void *)iph + ihl_len;
    } else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end)
            return TC_ACT_OK;
        if (ip6->nexthdr != IPPROTO_UDP && ip6->nexthdr != IPPROTO_TCP)
            return TC_ACT_OK;
        is_udp = ip6->nexthdr == IPPROTO_UDP;
        ipver = 6;
        __builtin_memcpy(key.ip, &ip6->saddr, 16);
        l4 = (void *)(ip6 + 1);
    } else {
        return TC_ACT_OK;
    }

    /* L4 解析：按协议各用正确的结构体读目的端口（UDP/TCP 头的前 4 字节布局相同，
     * 但类型分开写，绝不拿 udphdr 去解释 TCP 头）。每个分支都在自己的边界检查
     * 之后才解引用，并且只把**标量**带到分支之外——合并点之后不再出现指针，
     * verifier 无需跨分支推断包内边界。
     * udp_hdr_len / udp_src 只由 UDP 分支写入，也只被 UDP 的 SPA 候选路径读取。 */
    __u32 udp_hdr_len = 0;
    __u16 udp_src = 0;

    if (is_udp) {
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_OK;
        key.port = bpf_ntohs(udp->dest);
        udp_hdr_len = (__u32)((void *)(udp + 1) - data);
        udp_src = bpf_ntohs(udp->source);
    } else {
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_OK;
        key.port = bpf_ntohs(tcp->dest);
    }

    /* 1) allowlist：命中且未过期 → 打 mark 放行（全程内核内）。TCP 与 UDP 走的是
     * 同一条路径：受保护端口的业务 TCP（SSH）就靠这里拿到 MARK_KNOK。 */
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

    /* 2) SPA 候选：仅 UDP（M2）。TCP 在 allowlist 之后就直接返回，不做候选匹配，
     * 因此 cfg.spa_port 只在 UDP 路径上被读取；TCP 报文也不会因为目的端口恰好
     * 等于 SPA 端口而被上送（TCP SYN 匹配是 M4 的工作）。 */
    if (!is_udp)
        return TC_ACT_OK;

    __u32 zero = 0;
    struct cfg_val *c = bpf_map_lookup_elem(&cfg, &zero);
    if (!c || key.port != c->spa_port)
        return TC_ACT_OK;

    __u32 pkt_len = (__u32)(data_end - data);
    if (pkt_len < udp_hdr_len + 4)
        return TC_ACT_OK;
    __u32 plen = pkt_len - udp_hdr_len;

    __u8 magic[4];
    if (bpf_skb_load_bytes(skb, udp_hdr_len, magic, sizeof(magic)) < 0)
        return TC_ACT_OK;
    if (magic[0] != 'K' || magic[1] != 'N' || magic[2] != 'O' || magic[3] != 'K')
        return TC_ACT_OK;
    if (plen < c->min_len || plen > c->max_len)
        return TC_ACT_OK;

    __u32 copy_len = plen;
    if (copy_len > MAX_SPA_PKT)
        copy_len = MAX_SPA_PKT;

    /* verifier 提示：bpf_skb_load_bytes 的 size 参数是 ARG_CONST_SIZE，内核要求
     * 长度寄存器的 umin > 0，否则报 "invalid zero-sized read"。copy_len 的下界
     * 来自 map 值 cfg.min_len，verifier 无法证明它 ≥ 1，故这里补一个常量下界
     * （4 = magic 自身长度）。语义等价：上面的 pkt_len < udp_hdr_len + 4 已保证
     * plen ≥ 4，本分支在真实报文上永不触发。
     * 不要删除这一检查——删掉后程序会再次被 verifier 拒绝、加载不进内核。 */
    if (copy_len < 4)
        return TC_ACT_OK;

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
    e->src_port = udp_src;
    e->dst_port = key.port;
    e->payload_len = (__u16)copy_len;
    __builtin_memset(e->payload, 0, MAX_SPA_PKT);
    if (bpf_skb_load_bytes(skb, udp_hdr_len, e->payload, copy_len) < 0) {
        bpf_ringbuf_discard(e, 0);
        return TC_ACT_OK;
    }
    bump(ST_CANDIDATE);
    bpf_ringbuf_submit(e, 0);
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";

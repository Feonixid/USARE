/*
 * USARE TC Egress RST Filter — bpf_egress.c
 *
 * This program attaches at the TC (Traffic Control) EGRESS hook, which
 * intercepts packets LEAVING your machine BEFORE they reach the NIC.
 *
 * This is the correct hook for suppressing outgoing TCP RSTs that expose
 * Scapy raw-socket scanning to targets.  XDP is an INGRESS hook — it
 * cannot intercept outgoing packets in standard mode.
 *
 * Why outgoing RSTs snitch on you:
 *   Scapy sends raw SYNs bypassing the kernel TCP stack.
 *   When the target replies with SYN-ACK, the kernel sees an unexpected
 *   packet and RSTs it.  That RST tells the target the SYN was fake.
 *   Dropping that RST at TC egress means the target never sees it — from
 *   their perspective the connection just silently timed out.
 *
 * Attachment (root required):
 *   clang -O2 -target bpf -c bpf_egress.c -o bpf_egress.o \
 *         -I/usr/include -I/usr/include/x86_64-linux-gnu
 *   tc qdisc add dev eth0 clsact
 *   tc filter add dev eth0 egress bpf da obj bpf_egress.o sec tc_egress
 *
 * Detach:
 *   tc filter del dev eth0 egress
 *   tc qdisc del dev eth0 clsact
 *
 * Update target IPs at runtime (after loading):
 *   bpftool map update id <N> key 0 0 0 0 value <b0> <b1> <b2> <b3>
 *
 * Stats:
 *   bpftool map dump id <stats_id>
 *
 * Kernel requirement: >= 4.15 for TC BPF, >= 4.19 for clsact qdisc.
 * Verifier requirement: loop unrolling required (no bounded loops pre-5.3).
 */

#ifndef _WIN32
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#else
typedef unsigned int   __u32;
typedef unsigned short __u16;
typedef unsigned char  __u8;
typedef unsigned long long __u64;
#define TC_ACT_OK   0
#define TC_ACT_SHOT 2
struct __sk_buff { void *data; void *data_end; };
struct ethhdr { __u8 h_dest[6]; __u8 h_source[6]; __u16 h_proto; };
struct iphdr { __u8 ihl:4, version:4; __u8 tos; __u16 tot_len; __u16 id;
               __u16 frag_off; __u8 ttl; __u8 protocol; __u16 check;
               __u32 saddr; __u32 daddr; };
struct tcphdr { __u16 source; __u16 dest; __u32 seq; __u32 ack_seq;
                __u8 doff:4, res1:4; __u8 fin:1,syn:1,rst:1,psh:1,ack:1,urg:1,:2; };
#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6
#define bpf_htons(x) __builtin_bswap16(x)
static void *bpf_map_lookup_elem(void *m, void *k) { return 0; }
static void __sync_fetch_and_add(__u64 *p, int v) {}
#endif

#ifndef __section
# define __section(NAME) __attribute__((section(NAME), used))
#endif

/* ── tunables ────────────────────────────────────────────────────────── */
#define MAX_TARGETS      64
#define DROP_MODE_TARGETED  0   /* only drop RSTs to whitelisted IPs     */
#define DROP_MODE_ALL_RST   1   /* drop ALL outgoing RSTs on interface   */

/* ── BPF maps ────────────────────────────────────────────────────────── */

struct bpf_map_def __section("maps") eg_target_ips = {
    .type        = BPF_MAP_TYPE_ARRAY,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(__u32),
    .max_entries = MAX_TARGETS,
};

struct bpf_map_def __section("maps") eg_control_map = {
    .type        = BPF_MAP_TYPE_ARRAY,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(__u32),
    .max_entries = 1,
};

/* stats[0]=rst_seen, stats[1]=dropped, stats[2]=passed */
struct bpf_map_def __section("maps") eg_stats_map = {
    .type        = BPF_MAP_TYPE_ARRAY,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(__u64),
    .max_entries = 4,
};

/* ── helpers ─────────────────────────────────────────────────────────── */

static __always_inline void eg_stat_inc(__u32 idx) {
    __u64 *v = bpf_map_lookup_elem(&eg_stats_map, &idx);
    if (v) __sync_fetch_and_add(v, 1);
}

/*
 * Loop unrolled manually to satisfy the BPF verifier on kernels < 5.3.
 * Each iteration checks one slot.  MAX_TARGETS must equal the unroll count.
 * If you raise MAX_TARGETS you must add matching CHECK() macros.
 */
#define CHECK(slot) do {                                    \
    __u32 _k = (slot);                                     \
    __u32 *_e = bpf_map_lookup_elem(&eg_target_ips, &_k); \
    if (_e && *_e != 0 && *_e == dst_ip) return 1;        \
} while (0)

static __always_inline int eg_ip_is_target(__u32 dst_ip) {
    /* 64 slots — keep in sync with MAX_TARGETS */
    CHECK(0);  CHECK(1);  CHECK(2);  CHECK(3);
    CHECK(4);  CHECK(5);  CHECK(6);  CHECK(7);
    CHECK(8);  CHECK(9);  CHECK(10); CHECK(11);
    CHECK(12); CHECK(13); CHECK(14); CHECK(15);
    CHECK(16); CHECK(17); CHECK(18); CHECK(19);
    CHECK(20); CHECK(21); CHECK(22); CHECK(23);
    CHECK(24); CHECK(25); CHECK(26); CHECK(27);
    CHECK(28); CHECK(29); CHECK(30); CHECK(31);
    CHECK(32); CHECK(33); CHECK(34); CHECK(35);
    CHECK(36); CHECK(37); CHECK(38); CHECK(39);
    CHECK(40); CHECK(41); CHECK(42); CHECK(43);
    CHECK(44); CHECK(45); CHECK(46); CHECK(47);
    CHECK(48); CHECK(49); CHECK(50); CHECK(51);
    CHECK(52); CHECK(53); CHECK(54); CHECK(55);
    CHECK(56); CHECK(57); CHECK(58); CHECK(59);
    CHECK(60); CHECK(61); CHECK(62); CHECK(63);
    return 0;
}

/* ── TC egress program ───────────────────────────────────────────────── */

__section("tc_egress")
int tc_egress_rst_drop(struct __sk_buff *skb) {
    void *data     = (void *)(unsigned long)skb->data;
    void *data_end = (void *)(unsigned long)skb->data_end;

    /* ── Ethernet ── */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    /* ── IP ── */
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;
    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    /* ── TCP ── */
    __u32 ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < 20)
        return TC_ACT_OK;
    struct tcphdr *tcp = (void *)ip + ip_hdr_len;
    if ((void *)(tcp + 1) > data_end)
        return TC_ACT_OK;

    /* ── only act on RST packets ── */
    if (!tcp->rst) {
        eg_stat_inc(2);
        return TC_ACT_OK;
    }

    eg_stat_inc(0);  /* rst_seen */

    /* ── read drop mode ── */
    __u32 mode_key = 0;
    __u32 *mode_val = bpf_map_lookup_elem(&eg_control_map, &mode_key);
    __u32 drop_mode = (mode_val) ? *mode_val : DROP_MODE_TARGETED;

    int should_drop = 0;

    if (drop_mode == DROP_MODE_ALL_RST) {
        should_drop = 1;
    } else {
        /*
         * Targeted mode: drop RST only if destination IP is in our list.
         * ip->daddr is the destination of the outgoing RST —
         * i.e., the scan target we don't want to inform.
         */
        if (eg_ip_is_target(ip->daddr))
            should_drop = 1;
    }

    if (should_drop) {
        eg_stat_inc(1);
        return TC_ACT_SHOT;  /* TC equivalent of XDP_DROP — packet silently eaten */
    }

    eg_stat_inc(2);
    return TC_ACT_OK;
}

char _license[] __section("license") = "GPL";

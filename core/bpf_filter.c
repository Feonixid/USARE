/*
 * USARE eBPF XDP RST Filter — v2.0
 *
 * Improvements over v1:
 *   - BPF_MAP_TYPE_ARRAY for target IP whitelist (up to 64 targets)
 *   - Separate stats map: packets_dropped, packets_passed, rst_seen
 *   - Configurable drop mode via control map:
 *       mode 0 = only drop RSTs to whitelisted target IPs (default, safe)
 *       mode 1 = drop ALL RSTs on interface (original aggressive behaviour)
 *   - Correctly handles RST+ACK (connection refused) — still dropped when
 *     targeting a whitelisted IP because local OS must not reveal the scanner
 *   - Verifier-safe: all pointer arithmetic checked against data_end
 *
 * Requires: Linux kernel >= 4.15, clang/llc, ip link set dev xdp obj
 *
 * Build:
 *   clang -O2 -target bpf -c bpf_filter.c -o bpf_filter.o
 *
 * Load:
 *   ip link set dev eth0 xdp obj bpf_filter.o sec xdp
 *
 * Update targets from userspace (via bpftool map update or Python ctypes):
 *   bpftool map update id <N> key 0 0 0 0 value <ip_b0> <ip_b1> <ip_b2> <ip_b3>
 */

#ifndef _WIN32
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#else
/* Stub types for Windows IDE/linting only — not compiled */
typedef unsigned int   __u32;
typedef unsigned short __u16;
typedef unsigned char  __u8;
struct xdp_md { void *data; void *data_end; void *data_meta; };
#define ETH_P_IP 0x0800
struct ethhdr { __u8 h_dest[6]; __u8 h_source[6]; __u16 h_proto; };
struct iphdr  { __u8 ihl:4, version:4; __u8 tos; __u16 tot_len; __u16 id;
                __u16 frag_off; __u8 ttl; __u8 protocol; __u16 check;
                __u32 saddr; __u32 daddr; };
struct tcphdr { __u16 source; __u16 dest; __u32 seq; __u32 ack_seq;
                __u16 res1:4, doff:4, fin:1, syn:1, rst:1, psh:1,
                      ack:1, urg:1, ece:1, cwr:1; };
#define IPPROTO_TCP 6
#define bpf_htons(x) __builtin_bswap16(x)
#define XDP_DROP 1
#define XDP_PASS 2
static __attribute__((unused)) void *bpf_map_lookup_elem(void *m, void *k) { return 0; }
static __attribute__((unused)) int   bpf_map_update_elem(void *m, void *k, void *v, __u64 f) { return 0; }
#endif

#ifndef __section
# define __section(NAME) __attribute__((section(NAME), used))
#endif

/* ── constants ───────────────────────────────────────────────────────── */
#define MAX_TARGETS  64     /* max whitelisted target IPs                */
#define DROP_MODE_TARGETED  0
#define DROP_MODE_ALL_RST   1

/* ── BPF maps ────────────────────────────────────────────────────────── */

/* target_ips[0..MAX_TARGETS-1] — network-byte-order IPv4 addresses.
 * Zero entries are ignored.  Updated by userspace loader. */
struct bpf_map_def __section("maps") target_ips = {
    .type        = BPF_MAP_TYPE_ARRAY,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(__u32),
    .max_entries = MAX_TARGETS,
};

/* control[0] = drop mode (0=targeted, 1=all-rst) */
struct bpf_map_def __section("maps") control_map = {
    .type        = BPF_MAP_TYPE_ARRAY,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(__u32),
    .max_entries = 1,
};

/* stats[0]=rst_seen, stats[1]=dropped, stats[2]=passed */
struct bpf_map_def __section("maps") stats_map = {
    .type        = BPF_MAP_TYPE_ARRAY,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(__u64),
    .max_entries = 4,
};

/* ── helpers ─────────────────────────────────────────────────────────── */

static __always_inline void increment_stat(__u32 idx) {
    __u64 *val = bpf_map_lookup_elem(&stats_map, &idx);
    if (val)
        __sync_fetch_and_add(val, 1);
}

static __always_inline int ip_is_target(__u32 dst_ip) {
    for (__u32 i = 0; i < MAX_TARGETS; i++) {
        __u32 *entry = bpf_map_lookup_elem(&target_ips, &i);
        if (!entry)
            break;
        if (*entry == 0)
            continue;   /* empty slot */
        if (*entry == dst_ip)
            return 1;
    }
    return 0;
}

/* ── main XDP program ────────────────────────────────────────────────── */

__section("xdp")
int xdp_rst_drop(struct xdp_md *ctx) {
    void *data     = (void *)(unsigned long)ctx->data;
    void *data_end = (void *)(unsigned long)ctx->data_end;

    /* ── Ethernet ── */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* ── IP ── */
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    /* ── TCP ── */
    __u32 ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < 20)
        return XDP_PASS;
    struct tcphdr *tcp = (void *)ip + ip_hdr_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    /* ── only care about RST packets ── */
    if (!tcp->rst) {
        increment_stat(2);  /* passed (non-RST) */
        return XDP_PASS;
    }

    increment_stat(0);  /* rst_seen */

    /* ── read drop mode ── */
    __u32 mode_key = 0;
    __u32 *mode_val = bpf_map_lookup_elem(&control_map, &mode_key);
    __u32 drop_mode = (mode_val) ? *mode_val : DROP_MODE_TARGETED;

    int should_drop = 0;

    if (drop_mode == DROP_MODE_ALL_RST) {
        /* aggressive: drop every outgoing RST on this interface */
        should_drop = 1;
    } else {
        /* targeted: only drop RSTs to whitelisted IPs */
        if (ip_is_target(ip->daddr))
            should_drop = 1;
    }

    if (should_drop) {
        increment_stat(1);  /* dropped */
        return XDP_DROP;
    }

    increment_stat(2);  /* passed */
    return XDP_PASS;
}

char _license[] __section("license") = "GPL";

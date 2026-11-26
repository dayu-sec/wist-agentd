/*
 * 主机流记录：tc clsact 上的 egress / ingress 计数程序。
 *
 * 设计见 docs/design/host-ebpf-flow-collection.md：
 * - 只在 `__sk_buff` 暴露的字段上取值（len / gso_segs），**不用 CO-RE**，
 *   因此不依赖目标内核的 BTF；
 * - 在 BPF 侧按 (窗口, 网卡, 方向, 五元组) 聚合，用户态按窗口扫表 —— 不逐包上送；
 * - 不认识的协议、链路本地/组播、ICMPv6 邻居发现一律丢掉，并计入 drops。
 *
 * 方向由程序入口决定（两个程序分别挂 egress / ingress），不靠 skb 字段推断。
 *
 * 注意 BPF 的两个硬限制（踩过）：inline 函数最多 5 个参数（多了会退化成栈传参，
 * clang 直接报 "stack arguments are not supported"）；`__builtin_memcpy` 的长度必须是
 * 编译期常量（不能写 `family == 4 ? 4 : 16`）。
 */
#include <linux/bpf.h>

#include "bpf_min.h"

#define TC_ACT_OK 0

#define ETH_HLEN 14
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define ETH_P_8021Q 0x8100
#define ETH_P_8021AD 0x88A8

#define DIR_IN 0
#define DIR_OUT 1

#define FLAG_PORT_UNAVAILABLE 1
#define FLAG_WIRE_BYTES_MISSING 2

#define PROTO_ICMP 1
#define PROTO_TCP 6
#define PROTO_UDP 17
#define PROTO_ICMPV6 58

#define FLOW_WINDOW_NS 60000000000ULL

/* 与 Rust 侧 RawFlowKey 逐字节一致（packed，无隐式填充）。 */
struct flow_key {
    __u64 window_id;
    __u32 ifindex;
    __u8 direction;
    __u8 protocol;
    __u8 family;
    __u8 flags;
    __u8 src[16];
    __u8 dst[16];
    __u16 src_port; /* 网络序（原样），Rust 侧 from_be */
    __u16 dst_port;
    __u8 icmp_type;
    __u8 icmp_code;
    __u8 pad[6];
} __attribute__((packed));

/* 与 Rust 侧 RawFlowVal 逐字节一致。 */
struct flow_val {
    __u64 packets;    /* Σ gso_segs：估算的 L3 报文数 */
    __u64 bytes;      /* Σ skb->len：L3 字节，不含 L2 */
    __u64 wire_bytes; /* Σ wire_len：本版恒 0（不读 5.14+ 的 ctx 字段），保留字段给变体 */
    __u64 skb_count;  /* 观察到的 skb 数 */
    __u64 gso_skb_count;
    __u32 dropped;
    __u32 flags;
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct flow_key);
    __type(value, struct flow_val);
} flow_map SEC(".maps");

/* 每次 flush 由用户态读走并清零：非零 → 这一批记录不完整（表满被淘汰）。 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} drops SEC(".maps");

static __always_inline int proto_collected(__u8 proto)
{
    return proto == PROTO_TCP || proto == PROTO_UDP || proto == PROTO_ICMP ||
           proto == PROTO_ICMPV6;
}

static __always_inline int proto_has_ports(__u8 proto)
{
    return proto == PROTO_TCP || proto == PROTO_UDP;
}

/* 链路本地 / 组播 / 广播：对「和谁通信过」没有信息量，还会在 v6 主机上淹掉真实流量。 */
static __always_inline int v4_noise(const __u8 *a)
{
    return a[0] >= 224; /* 224/4 组播 + 240/4 保留（含 255.255.255.255） */
}

static __always_inline int v6_noise(const __u8 *a)
{
    int link_local = a[0] == 0xfe && (a[1] & 0xc0) == 0x80;
    int multicast = a[0] == 0xff;
    return link_local || multicast;
}

static __always_inline void note_drop(void)
{
    __u32 zero = 0;
    __u64 *counter = bpf_map_lookup_elem(&drops, &zero);
    if (counter)
        *counter += 1;
}

/* 只收三个参数：BPF inline 函数超过 5 个参数 clang 会退化成栈传参而拒绝编译。
 *
 * `l2_len` 必须传进来：tc 上 `skb->len` **包含以太头**（实测 57 = 14 + 43），
 * 而记录的 `bytes` 口径是 **L3**（设计 §8）。`wire_len` 是线缆长度，保持原样。 */
static __always_inline int account(struct __sk_buff *skb, struct flow_key *key, __u32 l2_len)
{
    key->window_id = bpf_ktime_get_ns() / FLOW_WINDOW_NS;
    key->ifindex = skb->ifindex;

    __u32 segments = skb->gso_segs ? skb->gso_segs : 1;
    __u32 l3_len = skb->len > l2_len ? skb->len - l2_len : skb->len;

    struct flow_val *value = bpf_map_lookup_elem(&flow_map, key);
    if (value) {
        value->packets += segments;
        value->bytes += l3_len;
        value->skb_count += 1;
        if (segments > 1)
            value->gso_skb_count += 1;
        /* `skb->wire_len` 是 5.14+ 的 ctx 字段：在 5.4/5.10 上访问它会让 verifier
         * **拒绝加载整个程序**（不是退化成 0）。为了守住 5.4 基线，这里不读它，
         * 线缆字节统一报 unavailable；5.14+ 的精确口径留给后续的程序变体。 */
        value->flags |= FLAG_WIRE_BYTES_MISSING;
        return TC_ACT_OK;
    }

    struct flow_val fresh = {};
    fresh.packets = segments;
    fresh.bytes = l3_len;
    fresh.skb_count = 1;
    fresh.gso_skb_count = segments > 1;
    fresh.flags = FLAG_WIRE_BYTES_MISSING;
    if (bpf_map_update_elem(&flow_map, key, &fresh, BPF_ANY) != 0) {
        /* LRU 满时会淘汰旧条目；更新失败说明真丢了，必须让用户态看见。 */
        note_drop();
    }
    return TC_ACT_OK;
}

static __always_inline int handle(struct __sk_buff *skb, __u8 direction)
{
    /* 按**包长**加载（上限 64）：
     * - 固定读 64 会让小于 64 字节的包（TCP ACK、UDP 探测、DNS 查询）整个失败；
     * - 用固定的几档（64/42/34）又会让"中间长度"的包丢端口 —— 例如 58 字节的 QinQ 帧
     *   （14 + 8 标签 + 20 + 8 + 8）端口落在 46，档位 42 就够不着。
     * 栈缓冲先清零：未加载的尾部是 0，verifier 也只接受已初始化的读。 */
    __u8 buf[64] = {};
    __u32 want = skb->len;
    if (want > 64)
        want = 64;
    /* 下界 34 = 以太(14) + IPv4(20)：再短连地址都读不全。
     * 必须给下界，否则 verifier 会按"可能为 0"拒绝变长读。 */
    if (want < 34)
        return TC_ACT_OK;
    if (bpf_skb_load_bytes(skb, 0, buf, want) < 0)
        return TC_ACT_OK;
    __u32 have = want;

    /* 剥 VLAN：单层 802.1Q 与 QinQ（802.1ad + 802.1Q）各一层，最多剥两层。
     * 每层 4 字节（TCI + 内层 ethertype）。 */
    __u32 l3 = ETH_HLEN;
    __u16 eth_proto = (__u16)((buf[12] << 8) | buf[13]);
#pragma unroll
    for (int tag = 0; tag < 2; tag++) {
        if (eth_proto != ETH_P_8021Q && eth_proto != ETH_P_8021AD)
            break;
        if (have < l3 + 4)
            return TC_ACT_OK;
        l3 += 4;
        eth_proto = (__u16)((buf[l3 - 2] << 8) | buf[l3 - 1]);
    }

    struct flow_key key = {};
    key.direction = direction;

    __u8 version = buf[l3] >> 4;
    if (eth_proto == ETH_P_IP && version == 4) {
        /* 截断帧：头都没读全时地址会是 0。宁可少一条，也不要一条 0.0.0.0 的假流。 */
        if (have < l3 + 20)
            return TC_ACT_OK;
        __u32 ihl = (__u32)(buf[l3] & 0x0f) * 4;
        if (ihl < 20 || ihl > 40)
            return TC_ACT_OK;
        __u8 protocol = buf[l3 + 9];
        if (!proto_collected(protocol))
            return TC_ACT_OK;
        const __u8 *src = &buf[l3 + 12];
        const __u8 *dst = &buf[l3 + 16];
        if (v4_noise(src) || v4_noise(dst)) {
            note_drop();
            return TC_ACT_OK;
        }
        key.family = 4;
        key.protocol = protocol;
        __builtin_memcpy(key.src, src, 4);
        __builtin_memcpy(key.dst, dst, 4);

        /* 分片：非首片没有端口，仍记录字节/报文，但标 port_unavailable（不做重组）。 */
        __u16 frag = (__u16)(((buf[l3 + 6] & 0x1f) << 8) | buf[l3 + 7]);
        __u32 port_at = l3 + ihl;
        if (frag & 0x1fff || port_at + 4 > have) {
            key.flags |= FLAG_PORT_UNAVAILABLE;
        } else {
            if (proto_has_ports(protocol)) {
                __builtin_memcpy(&key.src_port, &buf[port_at], 2);
                __builtin_memcpy(&key.dst_port, &buf[port_at + 2], 2);
            } else {
                key.icmp_type = buf[port_at];
                key.icmp_code = buf[port_at + 1];
            }
        }
        return account(skb, &key, l3);
    }

    if (eth_proto == ETH_P_IPV6 && version == 6) {
        if (have < l3 + 40)
            return TC_ACT_OK;
        __u8 protocol = buf[l3 + 6];
        if (!proto_collected(protocol)) {
            /* 扩展头（0 hop-by-hop / 43 routing / 44 fragment / 60 dest-opts）本版不解析。
             * 但要让这部分**可见**（进 drops）：否则 v6 主机上这段流量会无声消失。 */
            if (protocol == 0 || protocol == 43 || protocol == 44 || protocol == 60)
                note_drop();
            return TC_ACT_OK;
        }
        const __u8 *src = &buf[l3 + 8];
        const __u8 *dst = &buf[l3 + 24];
        if (v6_noise(src) || v6_noise(dst)) {
            note_drop();
            return TC_ACT_OK;
        }
        key.family = 6;
        key.protocol = protocol;
        __builtin_memcpy(key.src, src, 16);
        __builtin_memcpy(key.dst, dst, 16);

        /* 不做扩展头解析：端口只在「直接是 TCP/UDP/ICMPv6」时可得（见设计 §7.5）。 */
        __u32 port_at = l3 + 40;
        if (port_at + 4 > have) {
            key.flags |= FLAG_PORT_UNAVAILABLE;
            return account(skb, &key, l3);
        }
        if (proto_has_ports(protocol)) {
            __builtin_memcpy(&key.src_port, &buf[port_at], 2);
            __builtin_memcpy(&key.dst_port, &buf[port_at + 2], 2);
        } else {
            key.icmp_type = buf[port_at];
            key.icmp_code = buf[port_at + 1];
            /* ICMPv6 的 ND（133-137）与 MLD（130-132,143）是持续噪音。 */
            if (key.icmp_type >= 130 && key.icmp_type <= 143) {
                note_drop();
                return TC_ACT_OK;
            }
        }
        return account(skb, &key, l3);
    }

    return TC_ACT_OK;
}

SEC("classifier")
int flow_egress(struct __sk_buff *skb)
{
    return handle(skb, DIR_OUT);
}

SEC("classifier")
int flow_ingress(struct __sk_buff *skb)
{
    return handle(skb, DIR_IN);
}

char _license[] SEC("license") = "GPL";

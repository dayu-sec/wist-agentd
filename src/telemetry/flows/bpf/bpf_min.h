/*
 * 最小 BPF 头：只提供 SEC 宏、BTF map 宏与我们要用的几个 helper。
 *
 * 为什么不用 libbpf 的 bpf_helpers.h：构建机上不该为了一个 .o 去装 libbpf-dev；
 * 而 `struct __sk_buff` 的布局必须来自**系统 UAPI 头**（<linux/bpf.h>），不能手抄。
 */
#ifndef WIST_BPF_MIN_H
#define WIST_BPF_MIN_H

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

/* helper 编号见 kernel 的 include/uapi/linux/bpf.h（enum bpf_func_id）。 */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value,
                                   unsigned long long flags) = (void *)2;
static unsigned long long (*bpf_ktime_get_ns)(void) = (void *)5;
static long (*bpf_skb_load_bytes)(const void *ctx, unsigned int off, void *to,
                                  unsigned int len) = (void *)26;

#endif /* WIST_BPF_MIN_H */

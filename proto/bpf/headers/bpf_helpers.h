/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Minimal BPF helper stubs for clang/bpf target.
 * Avoids dependency on vmlinux.h or kernel headers.
 */
#ifndef __BPF_HELPERS_H
#define __BPF_HELPERS_H

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed char __s8;
typedef short __s16;
typedef int __s32;
typedef long long __s64;

/* Map definition macro (BTF-style) */
#define __uint(name, val) int(*name)[val]
#define __type(name, val) typeof(val) *name
#define __array(name, val) typeof(val) *name[]

/* Section helpers */
#define SEC(name) __attribute__((section(name), used))
#define __always_inline inline __attribute__((always_inline))

/* offsetof -- compiler built-in */
#ifndef offsetof
#define offsetof(TYPE, MEMBER) __builtin_offsetof(TYPE, MEMBER)
#endif

/* BPF map types */
enum bpf_map_type {
	BPF_MAP_TYPE_UNSPEC = 0,
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_ARRAY = 2,
	BPF_MAP_TYPE_PROG_ARRAY = 3,
	BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4,
	BPF_MAP_TYPE_PERCPU_HASH = 5,
	BPF_MAP_TYPE_PERCPU_ARRAY = 6,
	BPF_MAP_TYPE_STACK_TRACE = 7,
	BPF_MAP_TYPE_CGROUP_ARRAY = 8,
	BPF_MAP_TYPE_LRU_HASH = 9,
	BPF_MAP_TYPE_LRU_PERCPU_HASH = 10,
	BPF_MAP_TYPE_LPM_TRIE = 11,
	BPF_MAP_TYPE_ARRAY_OF_MAPS = 12,
	BPF_MAP_TYPE_HASH_OF_MAPS = 13,
	BPF_MAP_TYPE_DEVMAP = 14,
	BPF_MAP_TYPE_SOCKMAP = 15,
	BPF_MAP_TYPE_CPUMAP = 16,
	BPF_MAP_TYPE_XSKMAP = 17,
	BPF_MAP_TYPE_SOCKHASH = 18,
	BPF_MAP_TYPE_CGROUP_STORAGE = 19,
	BPF_MAP_TYPE_REUSEPORT_SOCKARRAY = 20,
	BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE = 21,
	BPF_MAP_TYPE_QUEUE = 22,
	BPF_MAP_TYPE_STACK = 23,
	BPF_MAP_TYPE_SK_STORAGE = 24,
	BPF_MAP_TYPE_DEVMAP_HASH = 25,
	BPF_MAP_TYPE_STRUCT_OPS = 26,
	BPF_MAP_TYPE_RINGBUF = 27,
};

/* Map flags */
#define BPF_F_NO_PREALLOC (1U << 0)

/* bpf_ringbuf_output flags */
#define BPF_RB_NO_WAKEUP (1ULL << 0)
#define BPF_RB_FORCE_WAKEUP (1ULL << 1)

/* Return codes for cgroup hooks */
#define BPF_OK 1
#define BPF_DROP 0

/* BPF helper function IDs -- stable UAPI numbers */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key,
				   const void *value,
				   __u64 flags) = (void *)2;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *)3;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)5;
static long (*bpf_get_current_pid_tgid)(void) = (void *)14;
static long (*bpf_get_current_uid_gid)(void) = (void *)15;
static long (*bpf_get_current_comm)(void *buf, __u32 size) = (void *)16;
static __u64 (*bpf_get_current_cgroup_id)(void) = (void *)80;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size,
				    __u64 flags) = (void *)131;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *)132;
static void (*bpf_ringbuf_discard)(void *data, __u64 flags) = (void *)133;

static long (*bpf_probe_read_str)(void *dst, __u32 size,
				 const void *src) = (void *)45;

/* Socket cookie -- available in cgroup sock_addr hooks (since 4.12). */
static __u64 (*bpf_get_socket_cookie_addr)(void *ctx) = (void *)46;

/* Socket cookie -- __sk_buff variant (tc/classifier programs). */
static __u64 (*bpf_get_socket_cookie)(void *ctx) = (void *)46;

/* L3 checksum replacement helper for rewriting IP header fields.
 * hdr_csum: offset of the checksum field from skb->data (bytes).
 * from: old value (network byte order, 2 or 4 bytes per sizeof flag).
 * to:   new value.
 * flags: BPF_F_PSEUDO_HDR (0x10) or 0; size encoded in low 4 bits (2 or 4).
 */
static long (*bpf_l3_csum_replace)(void *skb, __u32 hdr_csum,
				   __u64 from, __u64 to,
				   __u64 flags) = (void *)10;

/* Direct packet access helper -- load bytes from packet. */
static long (*bpf_skb_load_bytes)(void *skb, __u32 offset,
				  void *to, __u32 len) = (void *)26;

/* Direct packet store helper -- write bytes into packet. */
static long (*bpf_skb_store_bytes)(void *skb, __u32 offset,
				   const void *from, __u32 len,
				   __u64 flags) = (void *)9;

/* TC (traffic control) types and constants */

/* Minimal __sk_buff for tc classifier / action programs. */
struct __sk_buff {
	__u32 len;
	__u32 pkt_type;
	__u32 mark;
	__u32 queue_mapping;
	__u32 protocol;
	__u32 vlan_present;
	__u32 vlan_tci;
	__u32 vlan_proto;
	__u32 priority;
	__u32 ingress_ifindex;
	__u32 ifindex;
	__u32 tc_index;
	__u32 cb[5];
	__u32 hash;
	__u32 tc_classid;
	__u32 data;
	__u32 data_end;
	__u32 napi_id;
	__u32 family;
	__u32 remote_ip4;
	__u32 local_ip4;
	__u32 remote_ip6[4];
	__u32 local_ip6[4];
	__u32 remote_port;
	__u32 local_port;
};

/* TC action return codes */
#define TC_ACT_OK     0
#define TC_ACT_SHOT   2
#define TC_ACT_UNSPEC (-1)

/* bpf_skb_store_bytes flags */
#define BPF_F_RECOMPUTE_CSUM (1ULL << 0)

/* License */
#define LICENSE(s) char _license[] SEC("license") = (s)

#endif /* __BPF_HELPERS_H */

/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Shared data structures between BPF programs and userspace daemon.
 * Keep in sync with proto/daemon/types.go.
 */
#ifndef __PROCROUTE_COMMON_H
#define __PROCROUTE_COMMON_H

#include "bpf_helpers.h"

/* LPM trie key for IPv4 */
struct lpm_key_v4 {
	__u32 prefixlen;
	__u32 addr; /* network byte order */
};

/* LPM trie key for IPv6 */
struct lpm_key_v6 {
	__u32 prefixlen;
	__u8 addr[16]; /* network byte order */
};

/* Per-app LPM key: app_index prepended to address */
/*
 * The LPM trie matches on {app_index, addr} treated as a flat bit
 * string.  prefixlen covers both the app_index bits (always 32) and
 * the network prefix bits.
 *
 * Example: app_index=1, 10.0.0.0/8 -> prefixlen = 32 + 8 = 40
 */
struct app_lpm_key_v4 {
	__u32 prefixlen;
	__u32 app_index;
	__u32 addr; /* network byte order */
};

struct app_lpm_key_v6 {
	__u32 prefixlen;
	__u32 app_index;
	__u8 addr[16]; /* network byte order */
};

/* Allow-rule value stored alongside per-app LPM entries */
/*
 * port_lo == 0 && port_hi == 0 means "all ports allowed".
 * protocol: 6 = TCP, 17 = UDP, 0 = any.
 */
struct allow_rule {
	__u16 port_lo; /* host byte order */
	__u16 port_hi; /* host byte order */
	__u8 protocol; /* IPPROTO_TCP / IPPROTO_UDP / 0 */
	__u8 _pad[3];
};

/* Deny event sent to userspace ring buffer */
struct deny_event {
	__u64 timestamp_ns;
	__u64 cgroup_id;
	__u32 pid;
	__u32 uid;
	__u8 comm[16];
	__u8 af;      /* AF_INET=2, AF_INET6=10 */
	__u8 proto;   /* IPPROTO_TCP=6, IPPROTO_UDP=17 */
	__u16 dst_port; /* host byte order */
	union {
		__u32 dst_v4;     /* network byte order */
		__u8 dst_v6[16];  /* network byte order */
	};
	__u32 app_index; /* 0 = no app matched */
};

/* Exec event sent to userspace ring buffer */
struct exec_event {
	__u64 timestamp_ns;
	__u64 cgroup_id;
	__u32 tgid;
	__u32 app_index;
	__u8  comm[16];
};

/* Authorization epoch for revocation */
/*
 * auth_epoch: a single u64 counter incremented on every policy update.
 * socket_auth: maps socket cookie (u64) -> epoch (u64) at which the
 *   connection was authorized.  On sendmsg hooks, a mismatch between
 *   the socket's epoch and the current epoch triggers re-evaluation.
 */
struct revoke_event {
	__u64 timestamp_ns;
	__u64 cgroup_id;
	__u32 pid;
	__u32 uid;
	__u8  comm[16];
	__u8  af;
	__u8  proto;
	__u16 dst_port;
	union {
		__u32 dst_v4;
		__u8  dst_v6[16];
	};
	__u32 app_index;
	__u64 socket_cookie;
	__u64 old_epoch;
	__u64 cur_epoch;
};

/* Flow cache key for gateway enforcement */
/*
 * 5-tuple + protocol used as key for the flow_cache LRU hash.
 * All address/port fields are in network byte order.
 */
struct flow_cache_key {
	__u32 src_ip;
	__u32 dst_ip;
	__u16 src_port;
	__u16 dst_port;
	__u8  proto;
	__u8  _pad[3];
};

/* IPv6 flow cache key -- 5-tuple with 128-bit addresses */
struct flow_cache_key_v6 {
	__u8  src_ip[16];
	__u8  dst_ip[16];
	__u16 src_port;
	__u16 dst_port;
	__u8  proto;
	__u8  _pad[3];
};

/* Flow cache value: epoch at authorization time + ktime expiry. */
struct flow_cache_val {
	__u8  epoch;      /* epoch tag from ip->tos at authorization */
	__u8  _pad[3];
	__u32 app_index;  /* app_index that was authorized */
	__u64 expiry_ns;  /* ktime_ns deadline; 0 = no expiry */
};

/* Gateway deny event sent to userspace ring buffer */
struct gateway_deny_event {
	__u64 timestamp_ns;
	__u32 src_ip;     /* network byte order */
	__u32 dst_ip;     /* network byte order */
	__u16 src_port;   /* host byte order */
	__u16 dst_port;   /* host byte order */
	__u32 app_index;  /* from ntohs(ip->id), 0 = untagged */
	__u8  proto;      /* IPPROTO_TCP=6, IPPROTO_UDP=17 */
	__u8  _pad[7];
};

/* IPv6 gateway deny event */
struct gateway_deny_event_v6 {
	__u64 timestamp_ns;
	__u8  src_ip[16];   /* network byte order */
	__u8  dst_ip[16];   /* network byte order */
	__u16 src_port;     /* host byte order */
	__u16 dst_port;     /* host byte order */
	__u32 app_index;    /* from flow label, 0 = untagged */
	__u8  proto;
	__u8  _pad[7];
};

/* Hook runtime histogram */
/*
 * Per-hook runtime is recorded into log2-scale histogram buckets.
 * Bucket i covers [2^i, 2^(i+1)) nanoseconds.
 *   0: [1,   2)   ns     ~impossible
 *   1: [2,   4)   ns
 *   ...
 *   9: [512, 1024) ns     ~0.5-1 µs
 *  10: [1024, 2048) ns    ~1-2 µs
 *  ...
 *  20: [1M, 2M) ns        ~1-2 ms
 *  21: overflow (>=2M ns)
 *
 * Total: 22 buckets per outcome x 3 outcomes = 66 entries.
 * Outcomes: 0=ext_miss, 1=int_allow, 2=int_deny.
 */
#define HOOK_LAT_BUCKETS   22
#define HOOK_LAT_OUTCOMES  3

/* Outcome indices */
#define OUTCOME_EXT_MISS   0
#define OUTCOME_INT_ALLOW  1
#define OUTCOME_INT_DENY   2

/* Total per-CPU array entries: outcomes * buckets + outcomes (for count) */
#define HOOK_LAT_MAP_SIZE  (HOOK_LAT_OUTCOMES * HOOK_LAT_BUCKETS + HOOK_LAT_OUTCOMES)

/* Map layout:
 *   [0 .. 21]  = ext_miss histogram buckets
 *   [22 .. 43] = int_allow histogram buckets
 *   [44 .. 65] = int_deny histogram buckets
 *   [66]       = ext_miss total count
 *   [67]       = int_allow total count
 *   [68]       = int_deny total count
 */

/* Protocol numbers (avoid pulling in kernel headers) */
#define PROTO_TCP 6
#define PROTO_UDP 17

/* Address family */
#define AF_INET 2
#define AF_INET6 10

#endif /* __PROCROUTE_COMMON_H */

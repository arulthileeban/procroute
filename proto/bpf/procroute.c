// SPDX-License-Identifier: GPL-2.0
/*
 * ProcRoute -- eBPF cgroup sock_addr hooks for process-scoped route
 * authorization.
 *
 * Decision logic (same for all four programs):
 *   1. Extract dst IP / port / protocol.
 *   2. LPM lookup in internal_prefixes -- miss -> ALLOW (not internal).
 *   3. bpf_get_current_cgroup_id() -> lookup cgroup_to_app -- miss -> DENY.
 *   4. Composite LPM lookup in app_allow with {app_index, prefix} -- miss -> DENY.
 *   5. Check port range + protocol -- mismatch -> DENY.
 *   6. ALLOW.
 */

#include "headers/bpf_helpers.h"
#include "headers/bpf_endian.h"
#include "headers/common.h"

/* --- bpf_sock_addr context (minimal definition) --- */
struct bpf_sock_addr {
	__u32 user_family;
	__u32 user_ip4;      /* network byte order, connect4/sendmsg4 */
	__u32 user_ip6[4];   /* network byte order, connect6/sendmsg6 */
	__u32 user_port;     /* network byte order (big-endian __be16 in upper bits) */
	__u32 protocol;      /* IPPROTO_TCP or IPPROTO_UDP */
};

/* --- Maps --- */

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct lpm_key_v4);
	__type(value, __u8);
	__uint(max_entries, 1024);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} internal_prefixes_v4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct lpm_key_v6);
	__type(value, __u8);
	__uint(max_entries, 1024);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} internal_prefixes_v6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, __u32);
	__uint(max_entries, 4096);
} cgroup_to_app SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct app_lpm_key_v4);
	__type(value, struct allow_rule);
	__uint(max_entries, 8192);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} app_allow_v4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct app_lpm_key_v6);
	__type(value, struct allow_rule);
	__uint(max_entries, 8192);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} app_allow_v6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4 * 1024 * 1024); /* 4 MiB */
} deny_events SEC(".maps");


/* Expected SHA-256 hash per app_index. Presence means "requires verification." */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);      /* app_index */
	__type(value, __u8[32]); /* SHA-256 digest */
	__uint(max_entries, 256);
} app_exec_hash SEC(".maps");

/* Verified tasks: tgid -> app_index. Set by daemon after hash match. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);   /* tgid */
	__type(value, __u32); /* app_index */
	__uint(max_entries, 4096);
} task_verified SEC(".maps");

/* Exec event ring buffer for sched_process_exec notifications. */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024); /* 256 KiB */
} exec_events SEC(".maps");


/*
 * auth_epoch: index 0 holds the current epoch counter.
 * Incremented by the controller on every policy update.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 1);
} auth_epoch SEC(".maps");

/*
 * socket_auth: maps socket cookie -> epoch at authorization time.
 * Populated on allow verdict in connect4/connect6.
 * Checked on sendmsg4/sendmsg6 to detect stale authorizations.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);   /* socket cookie */
	__type(value, __u64); /* epoch */
	__uint(max_entries, 65536);
} socket_auth SEC(".maps");

/* Revocation event ring buffer (separate from deny_events). */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024); /* 256 KiB */
} revoke_events SEC(".maps");


/*
 * socket_to_app: populated by the tag-only BPF programs.
 * Records which application (by app_index) owns each socket.
 * Used for observability without enforcement.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u64);   /* socket cookie */
	__type(value, __u32); /* app_index (0 = unknown) */
	__uint(max_entries, 65536);
} socket_to_app SEC(".maps");


/*
 * exempt_ports: hash map of destination ports that should pass through
 * the gateway enforcer without tag/policy checks.  Used for out-of-band
 * control traffic (e.g. barrier sync during evaluation).
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u16);   /* destination port, host byte order */
	__type(value, __u8);  /* 1 = exempt */
	__uint(max_entries, 64);
} exempt_ports SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct flow_cache_key);
	__type(value, struct flow_cache_val);
	__uint(max_entries, 65536);
} flow_cache SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024); /* 256 KiB */
} gw_deny_events SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct flow_cache_key_v6);
	__type(value, struct flow_cache_val);
	__uint(max_entries, 65536);
} flow_cache_v6 SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} gw_deny_events_v6 SEC(".maps");


/*
 * flow_cache_config: array[1], index 0 = enabled flag.
 * 1 = cache enabled (default), 0 = cache disabled.
 * Controlled by the daemon via --no-flow-cache flag.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u8);
	__uint(max_entries, 1);
} flow_cache_config SEC(".maps");


/*
 * flow_cache_stats: per-CPU array[3].
 *   index 0 = hits   (cache lookup succeeded and was valid)
 *   index 1 = misses (cache lookup failed or entry was stale)
 *   index 2 = inserts (new entry written into the cache)
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 3);
} flow_cache_stats SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, HOOK_LAT_MAP_SIZE);
} hook_latency SEC(".maps");

/* Record a latency sample into the histogram.
 * outcome: OUTCOME_EXT_MISS / OUTCOME_INT_ALLOW / OUTCOME_INT_DENY
 * delta_ns: elapsed nanoseconds for this hook invocation.
 */
static __always_inline void record_latency(__u32 outcome, __u64 delta_ns)
{
	__u32 bucket = 0;
	__u64 v = delta_ns;

	/* Manual log2 via bit shifts (BPF verifier-friendly) */
	if (v >= (1ULL << 16)) { bucket += 16; v >>= 16; }
	if (v >= (1ULL <<  8)) { bucket +=  8; v >>=  8; }
	if (v >= (1ULL <<  4)) { bucket +=  4; v >>=  4; }
	if (v >= (1ULL <<  2)) { bucket +=  2; v >>=  2; }
	if (v >= (1ULL <<  1)) { bucket +=  1; }

	if (bucket >= HOOK_LAT_BUCKETS)
		bucket = HOOK_LAT_BUCKETS - 1;

	__u32 idx = outcome * HOOK_LAT_BUCKETS + bucket;
	__u64 *cnt = bpf_map_lookup_elem(&hook_latency, &idx);
	if (cnt)
		__sync_fetch_and_add(cnt, 1);

	__u32 total_idx = HOOK_LAT_OUTCOMES * HOOK_LAT_BUCKETS + outcome;
	__u64 *total = bpf_map_lookup_elem(&hook_latency, &total_idx);
	if (total)
		__sync_fetch_and_add(total, 1);
}


static __always_inline __u64 get_current_epoch(void)
{
	__u32 zero = 0;
	__u64 *ep = bpf_map_lookup_elem(&auth_epoch, &zero);
	return ep ? *ep : 0;
}

/* Stamp a socket cookie with the current epoch on allow. */
static __always_inline void stamp_socket(void *ctx)
{
	__u64 cookie = bpf_get_socket_cookie_addr(ctx);
	__u64 epoch = get_current_epoch();
	bpf_map_update_elem(&socket_auth, &cookie, &epoch, 0 /* BPF_ANY */);
}

/* Check if the socket's authorization is stale.  Returns 1 if stale. */
static __always_inline int is_stale_socket(void *ctx)
{
	__u64 cur = get_current_epoch();
	if (cur == 0)
		return 0; /* epoch not initialized -> no revocation active */

	__u64 cookie = bpf_get_socket_cookie_addr(ctx);
	__u64 *auth_ep = bpf_map_lookup_elem(&socket_auth, &cookie);
	if (!auth_ep)
		return 0; /* no epoch stamp -> first use, will be evaluated normally */

	return (*auth_ep < cur) ? 1 : 0;
}

static __always_inline void emit_revoke_v4(void *ctx, __u32 dst_ip,
					   __u16 dst_port, __u8 proto,
					   __u32 app_index)
{
	struct revoke_event *evt;
	evt = bpf_ringbuf_reserve(&revoke_events, sizeof(*evt), 0);
	if (!evt)
		return;

	__u64 cookie = bpf_get_socket_cookie_addr(ctx);
	__u64 cur = get_current_epoch();
	__u64 *old = bpf_map_lookup_elem(&socket_auth, &cookie);

	evt->timestamp_ns = bpf_ktime_get_ns();
	evt->cgroup_id = bpf_get_current_cgroup_id();
	evt->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	evt->uid = (__u32)bpf_get_current_uid_gid();
	bpf_get_current_comm(evt->comm, sizeof(evt->comm));
	evt->af = AF_INET;
	evt->proto = proto;
	evt->dst_port = dst_port;
	evt->dst_v4 = dst_ip;
	evt->app_index = app_index;
	evt->socket_cookie = cookie;
	evt->old_epoch = old ? *old : 0;
	evt->cur_epoch = cur;

	bpf_ringbuf_submit(evt, 0);

	bpf_map_delete_elem(&socket_auth, &cookie);
}


static __always_inline void emit_deny_v4(__u32 dst_ip, __u16 dst_port,
					 __u8 proto, __u32 app_index)
{
	struct deny_event *evt;

	evt = bpf_ringbuf_reserve(&deny_events, sizeof(*evt), 0);
	if (!evt)
		return;

	evt->timestamp_ns = bpf_ktime_get_ns();
	evt->cgroup_id = bpf_get_current_cgroup_id();
	evt->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	evt->uid = (__u32)bpf_get_current_uid_gid();
	bpf_get_current_comm(evt->comm, sizeof(evt->comm));
	evt->af = AF_INET;
	evt->proto = proto;
	evt->dst_port = dst_port;
	evt->dst_v4 = dst_ip;
	evt->app_index = app_index;

	bpf_ringbuf_submit(evt, 0);
}

static __always_inline void emit_deny_v6(__u8 dst_ip[16], __u16 dst_port,
					 __u8 proto, __u32 app_index)
{
	struct deny_event *evt;

	evt = bpf_ringbuf_reserve(&deny_events, sizeof(*evt), 0);
	if (!evt)
		return;

	evt->timestamp_ns = bpf_ktime_get_ns();
	evt->cgroup_id = bpf_get_current_cgroup_id();
	evt->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	evt->uid = (__u32)bpf_get_current_uid_gid();
	bpf_get_current_comm(evt->comm, sizeof(evt->comm));
	evt->af = AF_INET6;
	evt->proto = proto;
	evt->dst_port = dst_port;
	__builtin_memcpy(evt->dst_v6, dst_ip, 16);
	evt->app_index = app_index;

	bpf_ringbuf_submit(evt, 0);
}

static __always_inline int check_port_proto(struct allow_rule *rule,
					    __u16 port, __u8 proto)
{
	if (rule->protocol != 0 && rule->protocol != proto)
		return 0;

	/* Port check: 0/0 = all ports allowed */
	if (rule->port_lo == 0 && rule->port_hi == 0)
		return 1;

	if (port >= rule->port_lo && port <= rule->port_hi)
		return 1;

	return 0;
}


/*
 * resolve_app_index: derive app_index from the current cgroup,
 * including the exec_hash verification gate.
 * Returns the app_index (>= 1) on success, or 0 if no app matched
 * or the binary hash was not verified.
 */
static __always_inline __u32 resolve_app_index(void)
{
	__u64 cgid = bpf_get_current_cgroup_id();
	__u32 *app_idx = bpf_map_lookup_elem(&cgroup_to_app, &cgid);
	if (!app_idx)
		return 0;

	/* Binary hash verification gate: if the app requires it,
	 * check that the current task has been verified.
	 */
	if (bpf_map_lookup_elem(&app_exec_hash, app_idx)) {
		__u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
		__u32 *vid = bpf_map_lookup_elem(&task_verified, &tgid);
		if (!vid || *vid != *app_idx)
			return 0;
	}

	return *app_idx;
}

/* --- IPv4 decision logic --- */

/*
 * is_connect: 1 for connect4 (stamp socket on allow),
 *             0 for sendmsg4 (check epoch staleness).
 */
static __always_inline int decide_v4(struct bpf_sock_addr *ctx, __u8 proto,
				     int is_connect)
{
	__u64 t_start = bpf_ktime_get_ns();

	__u32 dst_ip = ctx->user_ip4;
	/* user_port is __be32 with the port in the upper 16 bits on
	 * little-endian; bpf_ntohl then shift gives host-order port. */
	__u16 dst_port = (__u16)(bpf_ntohl(ctx->user_port) >> 16);

	/* Step 0 (sendmsg only): epoch staleness check.
	 * If the socket was authorized under an older epoch and the
	 * destination is internal, emit a revocation event and deny.
	 */
	if (!is_connect && is_stale_socket(ctx)) {
		/* Check if destination is internal before revoking */
		struct lpm_key_v4 skey = { .prefixlen = 32, .addr = dst_ip };
		if (bpf_map_lookup_elem(&internal_prefixes_v4, &skey)) {
			__u64 cgid = bpf_get_current_cgroup_id();
			__u32 *aidx = bpf_map_lookup_elem(&cgroup_to_app, &cgid);
			emit_revoke_v4(ctx, dst_ip, dst_port, proto,
				       aidx ? *aidx : 0);
			record_latency(OUTCOME_INT_DENY,
				       bpf_ktime_get_ns() - t_start);
			return BPF_DROP;
		}
	}

	/* Step 1: is destination an internal prefix? */
	struct lpm_key_v4 ikey = {
		.prefixlen = 32,
		.addr = dst_ip,
	};
	if (!bpf_map_lookup_elem(&internal_prefixes_v4, &ikey)) {
		record_latency(OUTCOME_EXT_MISS,
			       bpf_ktime_get_ns() - t_start);
		return BPF_OK; /* not internal -> allow */
	}

	/* Step 2: which app is this cgroup? */
	__u64 cgid = bpf_get_current_cgroup_id();
	__u32 *app_idx = bpf_map_lookup_elem(&cgroup_to_app, &cgid);
	if (!app_idx) {
		emit_deny_v4(dst_ip, dst_port, proto, 0);
		record_latency(OUTCOME_INT_DENY,
			       bpf_ktime_get_ns() - t_start);
		return BPF_DROP;
	}

	/* Step 2.5: binary hash verification gate */
	if (bpf_map_lookup_elem(&app_exec_hash, app_idx)) {
		__u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
		__u32 *vid = bpf_map_lookup_elem(&task_verified, &tgid);
		if (!vid || *vid != *app_idx) {
			emit_deny_v4(dst_ip, dst_port, proto, *app_idx);
			record_latency(OUTCOME_INT_DENY,
				       bpf_ktime_get_ns() - t_start);
			return BPF_DROP;
		}
	}

	/* Step 3: per-app LPM lookup */
	struct app_lpm_key_v4 akey = {
		.prefixlen = 32 + 32, /* full app_index + full IPv4 */
		.app_index = *app_idx,
		.addr = dst_ip,
	};
	struct allow_rule *rule =
		bpf_map_lookup_elem(&app_allow_v4, &akey);
	if (!rule) {
		emit_deny_v4(dst_ip, dst_port, proto, *app_idx);
		record_latency(OUTCOME_INT_DENY,
			       bpf_ktime_get_ns() - t_start);
		return BPF_DROP;
	}

	/* Step 4: port + protocol check */
	if (!check_port_proto(rule, dst_port, proto)) {
		emit_deny_v4(dst_ip, dst_port, proto, *app_idx);
		record_latency(OUTCOME_INT_DENY,
			       bpf_ktime_get_ns() - t_start);
		return BPF_DROP;
	}

	/* Stamp the socket with the current epoch on allow */
	stamp_socket(ctx);
	record_latency(OUTCOME_INT_ALLOW, bpf_ktime_get_ns() - t_start);
	return BPF_OK;
}

/* --- IPv6 decision logic --- */

static __always_inline int decide_v6(struct bpf_sock_addr *ctx, __u8 proto,
				     int is_connect)
{
	__u64 t_start = bpf_ktime_get_ns();

	__u8 dst_ip[16];
	__builtin_memcpy(dst_ip, ctx->user_ip6, 16);
	__u16 dst_port = (__u16)(bpf_ntohl(ctx->user_port) >> 16);

	/* Step 1: is destination an internal prefix? */
	struct lpm_key_v6 ikey = { .prefixlen = 128 };
	__builtin_memcpy(ikey.addr, dst_ip, 16);

	if (!bpf_map_lookup_elem(&internal_prefixes_v6, &ikey)) {
		record_latency(OUTCOME_EXT_MISS,
			       bpf_ktime_get_ns() - t_start);
		return BPF_OK; /* not internal -> allow */
	}

	/* Step 2: which app is this cgroup? */
	__u64 cgid = bpf_get_current_cgroup_id();
	__u32 *app_idx = bpf_map_lookup_elem(&cgroup_to_app, &cgid);
	if (!app_idx) {
		emit_deny_v6(dst_ip, dst_port, proto, 0);
		record_latency(OUTCOME_INT_DENY,
			       bpf_ktime_get_ns() - t_start);
		return BPF_DROP;
	}

	/* Step 2.5: binary hash verification gate */
	if (bpf_map_lookup_elem(&app_exec_hash, app_idx)) {
		__u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
		__u32 *vid = bpf_map_lookup_elem(&task_verified, &tgid);
		if (!vid || *vid != *app_idx) {
			emit_deny_v6(dst_ip, dst_port, proto, *app_idx);
			record_latency(OUTCOME_INT_DENY,
				       bpf_ktime_get_ns() - t_start);
			return BPF_DROP;
		}
	}

	/* Step 3: per-app LPM lookup */
	struct app_lpm_key_v6 akey = { .prefixlen = 32 + 128 };
	akey.app_index = *app_idx;
	__builtin_memcpy(akey.addr, dst_ip, 16);

	struct allow_rule *rule =
		bpf_map_lookup_elem(&app_allow_v6, &akey);
	if (!rule) {
		emit_deny_v6(dst_ip, dst_port, proto, *app_idx);
		record_latency(OUTCOME_INT_DENY,
			       bpf_ktime_get_ns() - t_start);
		return BPF_DROP;
	}

	/* Step 4: port + protocol check */
	if (!check_port_proto(rule, dst_port, proto)) {
		emit_deny_v6(dst_ip, dst_port, proto, *app_idx);
		record_latency(OUTCOME_INT_DENY,
			       bpf_ktime_get_ns() - t_start);
		return BPF_DROP;
	}

	stamp_socket(ctx);
	record_latency(OUTCOME_INT_ALLOW, bpf_ktime_get_ns() - t_start);
	return BPF_OK;
}

/* --- Programs --- */

SEC("cgroup/connect4")
int procroute_connect4(struct bpf_sock_addr *ctx)
{
	return decide_v4(ctx, PROTO_TCP, 1 /* is_connect */);
}

SEC("cgroup/connect6")
int procroute_connect6(struct bpf_sock_addr *ctx)
{
	return decide_v6(ctx, PROTO_TCP, 1 /* is_connect */);
}

SEC("cgroup/sendmsg4")
int procroute_sendmsg4(struct bpf_sock_addr *ctx)
{
	return decide_v4(ctx, PROTO_UDP, 0 /* is_sendmsg */);
}

SEC("cgroup/sendmsg6")
int procroute_sendmsg6(struct bpf_sock_addr *ctx)
{
	return decide_v6(ctx, PROTO_UDP, 0 /* is_sendmsg */);
}

/* --- Tag-only programs (observe, never deny) --- */

/*
 * Tag-only mode: resolve app_index and record it in socket_to_app
 * keyed by socket cookie.  Always returns BPF_OK -- no enforcement.
 * These programs are attached instead of procroute_* when the daemon
 * runs with --mode tag-only.
 */

SEC("cgroup/connect4")
int procroute_tag_connect4(struct bpf_sock_addr *ctx)
{
	__u32 idx = resolve_app_index();
	__u64 cookie = bpf_get_socket_cookie_addr(ctx);
	bpf_map_update_elem(&socket_to_app, &cookie, &idx, 0 /* BPF_ANY */);
	return BPF_OK;
}

SEC("cgroup/connect6")
int procroute_tag_connect6(struct bpf_sock_addr *ctx)
{
	__u32 idx = resolve_app_index();
	__u64 cookie = bpf_get_socket_cookie_addr(ctx);
	bpf_map_update_elem(&socket_to_app, &cookie, &idx, 0 /* BPF_ANY */);
	return BPF_OK;
}

SEC("cgroup/sendmsg4")
int procroute_tag_sendmsg4(struct bpf_sock_addr *ctx)
{
	__u32 idx = resolve_app_index();
	__u64 cookie = bpf_get_socket_cookie_addr(ctx);
	bpf_map_update_elem(&socket_to_app, &cookie, &idx, 0 /* BPF_ANY */);
	return BPF_OK;
}

SEC("cgroup/sendmsg6")
int procroute_tag_sendmsg6(struct bpf_sock_addr *ctx)
{
	__u32 idx = resolve_app_index();
	__u64 cookie = bpf_get_socket_cookie_addr(ctx);
	bpf_map_update_elem(&socket_to_app, &cookie, &idx, 0 /* BPF_ANY */);
	return BPF_OK;
}


struct iphdr {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	__u8 ihl:4,
	     version:4;
#else
	__u8 version:4,
	     ihl:4;
#endif
	__u8  tos;
	__u16 tot_len;
	__u16 id;
	__u16 frag_off;
	__u8  ttl;
	__u8  protocol;
	__u16 check;
	__u32 saddr;
	__u32 daddr;
};


struct ipv6hdr {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	__u8  tc_hi:4, version:4;
	__u8  flow_hi:4, tc_lo:4;
#else
	__u8  version:4, tc_hi:4;
	__u8  tc_lo:4, flow_hi:4;
#endif
	__u16 flow_lo;
	__u16 payload_len;
	__u8  nexthdr;
	__u8  hop_limit;
	__u8  saddr[16];
	__u8  daddr[16];
};

/* --- TC egress tagger for WireGuard client --- */

/*
 * procroute_wg_tag_egress: attached to wg0 tc egress on the client.
 *
 * For each outgoing IPv4 packet, looks up the socket cookie in
 * socket_to_app to find the app_index, then encodes:
 *   ip->tos = (u8)(current_epoch & 0xff)
 *   ip->id  = htons(app_index)
 *
 * The gateway reads these fields to enforce per-app policy.
 * Always returns TC_ACT_OK -- tagging never drops packets.
 */
SEC("tc")
int procroute_wg_tag_egress(struct __sk_buff *skb)
{
	/* Read the first 20 bytes (minimal IPv4 header) via safe helper */
	struct iphdr iph;
	if (bpf_skb_load_bytes(skb, 0, &iph, sizeof(iph)) < 0)
		return TC_ACT_OK;

	if (iph.version != 4)
		return TC_ACT_OK;

	/* Look up app_index from socket cookie */
	__u64 cookie = bpf_get_socket_cookie(skb);
	__u32 app_index = 0;
	__u32 *idx = bpf_map_lookup_elem(&socket_to_app, &cookie);
	if (idx)
		app_index = *idx;

	/* Read current epoch */
	__u8 epoch_tag = (__u8)(get_current_epoch() & 0xff);

	__u8  old_tos = iph.tos;
	__u16 old_id  = iph.id;
	__u16 new_id  = bpf_htons((__u16)app_index);

	/* Update TOS field: use l3_csum_replace for incremental checksum,
	 * then store the byte.  TOS is at byte offset 1.
	 * For 2-byte csum update, treat TOS as the high byte of the
	 * first 16-bit word of the header (version/ihl, tos).
	 */
	if (old_tos != epoch_tag) {
		bpf_l3_csum_replace(skb, offsetof(struct iphdr, check),
				    bpf_htons((__u16)old_tos << 8),
				    bpf_htons((__u16)epoch_tag << 8), 2);
		bpf_skb_store_bytes(skb, offsetof(struct iphdr, tos),
				    &epoch_tag, sizeof(epoch_tag), 0);
	}

	/* Update ID field (2 bytes, at offset 4) */
	if (old_id != new_id) {
		bpf_l3_csum_replace(skb, offsetof(struct iphdr, check),
				    old_id, new_id, 2);
		bpf_skb_store_bytes(skb, offsetof(struct iphdr, id),
				    &new_id, sizeof(new_id), 0);
	}

	return TC_ACT_OK;
}


struct tcphdr {
	__u16 source;
	__u16 dest;
	__u32 seq;
	__u32 ack_seq;
	__u16 flags;      /* data offset + flags -- we only need dest port */
	__u16 window;
	__u16 check;
	__u16 urg_ptr;
};


struct udphdr {
	__u16 source;
	__u16 dest;
	__u16 len;
	__u16 check;
};

#define FLOW_CACHE_TTL_NS (5ULL * 1000000000ULL)

/* --- TC ingress enforcer for WireGuard gateway --- */

/*
 * procroute_wg_enforce_ingress: attached to wg0 tc ingress on the gateway.
 *
 * For each incoming IPv4 packet from a WireGuard peer:
 *   1. Parse IPv4 header safely via bpf_skb_load_bytes.
 *   2. Read app_index from ntohs(ip->id) -- set by client tagger.
 *   3. Drop immediately if app_index == 0 (untagged).
 *   4. Extract dst_ip, dst_port, proto (TCP/UDP parsing).
 *   5. Check flow_cache fast path (epoch match + not expired).
 *   6. On miss: policy lookup using app_allow_v4 LPM trie.
 *   7. On allow: clear ip->tos and ip->id, update checksum,
 *      update flow_cache, return TC_ACT_OK.
 *   8. On deny: emit gateway_deny_event, return TC_ACT_SHOT.
 */
SEC("tc")
int procroute_wg_enforce_ingress(struct __sk_buff *skb)
{
	/* Read the minimal IPv4 header */
	struct iphdr iph;
	if (bpf_skb_load_bytes(skb, 0, &iph, sizeof(iph)) < 0)
		return TC_ACT_OK; /* can't parse -> pass through */

	/* Only enforce IPv4 */
	if (iph.version != 4)
		return TC_ACT_OK;

	/* Calculate IP header length */
	__u32 ihl = (__u32)iph.ihl * 4;
	if (ihl < 20 || ihl > 60)
		return TC_ACT_SHOT;

	/* Extract dst_ip, src_ip */
	__u32 dst_ip = iph.daddr;
	__u32 src_ip = iph.saddr;
	__u8  proto  = iph.protocol;

	/* Extract src_port and dst_port based on protocol */
	__u16 src_port = 0;
	__u16 dst_port = 0;

	if (proto == PROTO_TCP) {
		struct tcphdr th;
		if (bpf_skb_load_bytes(skb, ihl, &th, sizeof(th)) < 0)
			return TC_ACT_SHOT;
		src_port = bpf_ntohs(th.source);
		dst_port = bpf_ntohs(th.dest);
	} else if (proto == PROTO_UDP) {
		struct udphdr uh;
		if (bpf_skb_load_bytes(skb, ihl, &uh, sizeof(uh)) < 0)
			return TC_ACT_SHOT;
		src_port = bpf_ntohs(uh.source);
		dst_port = bpf_ntohs(uh.dest);
	}
	/* For other protocols (ICMP, etc.), ports stay 0 */

	/* Check exempt ports before enforcing tags */
	if (bpf_map_lookup_elem(&exempt_ports, &dst_port))
		return TC_ACT_OK;

	/* Read app_index from the tagged ip->id field */
	__u32 app_index = (__u32)bpf_ntohs(iph.id);

	/* Drop untagged packets to internal destinations */
	if (app_index == 0)
		return TC_ACT_SHOT;

	/* Read epoch from ip->tos tag */
	__u8 epoch_tag = iph.tos;

	
	__u32 fc_cfg_key = 0;
	__u8 *fc_enabled = bpf_map_lookup_elem(&flow_cache_config, &fc_cfg_key);
	int cache_on = fc_enabled ? (*fc_enabled != 0) : 1; /* default: enabled */

	
	struct flow_cache_key fkey = {
		.src_ip   = src_ip,
		.dst_ip   = dst_ip,
		.src_port = bpf_htons(src_port),
		.dst_port = bpf_htons(dst_port),
		.proto    = proto,
	};

	if (cache_on) {
		struct flow_cache_val *fval =
			bpf_map_lookup_elem(&flow_cache, &fkey);
		if (fval) {
			__u64 now = bpf_ktime_get_ns();
			if (fval->epoch == epoch_tag &&
			    fval->app_index == app_index &&
			    (fval->expiry_ns == 0 || now < fval->expiry_ns)) {
				/* Cache hit -- increment stats, allow */
				__u32 hit_key = 0;
				__u64 *hit_cnt = bpf_map_lookup_elem(
					&flow_cache_stats, &hit_key);
				if (hit_cnt)
					__sync_fetch_and_add(hit_cnt, 1);
				goto allow;
			}
		}
		/* Cache miss -- increment stats */
		__u32 miss_key = 1;
		__u64 *miss_cnt = bpf_map_lookup_elem(
			&flow_cache_stats, &miss_key);
		if (miss_cnt)
			__sync_fetch_and_add(miss_cnt, 1);
	}

	/* slow path */
	{
		/* Check if destination is an internal prefix */
		struct lpm_key_v4 ikey = {
			.prefixlen = 32,
			.addr = dst_ip,
		};
		if (!bpf_map_lookup_elem(&internal_prefixes_v4, &ikey)) {
			/* Not internal -- allow without cache update */
			goto allow;
		}

		/* Per-app LPM lookup */
		struct app_lpm_key_v4 akey = {
			.prefixlen = 32 + 32,
			.app_index = app_index,
			.addr = dst_ip,
		};
		struct allow_rule *rule =
			bpf_map_lookup_elem(&app_allow_v4, &akey);
		if (!rule) {
			goto deny;
		}

		/* Port + protocol check */
		if (!check_port_proto(rule, dst_port, proto)) {
			goto deny;
		}

		/* Update flow cache on allow (only if cache is enabled) */
		if (cache_on) {
			struct flow_cache_val new_fval = {
				.epoch     = epoch_tag,
				.app_index = app_index,
				.expiry_ns = bpf_ktime_get_ns() + FLOW_CACHE_TTL_NS,
			};
			bpf_map_update_elem(&flow_cache, &fkey, &new_fval,
					    0 /* BPF_ANY */);
			/* Increment insert counter */
			__u32 ins_key = 2;
			__u64 *ins_cnt = bpf_map_lookup_elem(
				&flow_cache_stats, &ins_key);
			if (ins_cnt)
				__sync_fetch_and_add(ins_cnt, 1);
		}
	}

allow:
	/* Clear ip->tos and ip->id, update checksum */
	{
		__u8  old_tos = iph.tos;
		__u16 old_id  = iph.id;
		__u8  zero_tos = 0;
		__u16 zero_id  = 0;

		if (old_tos != 0) {
			bpf_l3_csum_replace(skb,
				offsetof(struct iphdr, check),
				bpf_htons((__u16)old_tos << 8),
				0, 2);
			bpf_skb_store_bytes(skb,
				offsetof(struct iphdr, tos),
				&zero_tos, sizeof(zero_tos), 0);
		}

		if (old_id != 0) {
			bpf_l3_csum_replace(skb,
				offsetof(struct iphdr, check),
				old_id, 0, 2);
			bpf_skb_store_bytes(skb,
				offsetof(struct iphdr, id),
				&zero_id, sizeof(zero_id), 0);
		}
	}
	return TC_ACT_OK;

deny:
	/* Emit gateway deny event */
	{
		struct gateway_deny_event *evt;
		evt = bpf_ringbuf_reserve(&gw_deny_events, sizeof(*evt), 0);
		if (evt) {
			evt->timestamp_ns = bpf_ktime_get_ns();
			evt->src_ip    = src_ip;
			evt->dst_ip    = dst_ip;
			evt->src_port  = src_port;
			evt->dst_port  = dst_port;
			evt->app_index = app_index;
			evt->proto     = proto;
			bpf_ringbuf_submit(evt, 0);
		}
	}
	return TC_ACT_SHOT;
}

/* --- TC egress tagger for WireGuard client (IPv6) --- */

/*
 * procroute_wg_tag_egress_v6: attached to wg0 tc egress on the client.
 *
 * For each outgoing IPv6 packet, looks up the socket cookie in
 * socket_to_app to find the app_index, then encodes:
 *   flow_label (20 bits) = app_index (principal_id)
 *   traffic_class (8 bits) = epoch_low8
 *
 * IPv6 has no header checksum, so no checksum update is needed.
 * Always returns TC_ACT_OK -- tagging never drops packets.
 */
SEC("tc")
int procroute_wg_tag_egress_v6(struct __sk_buff *skb)
{
	/* Read the IPv6 header (40 bytes) */
	struct ipv6hdr ip6h;
	if (bpf_skb_load_bytes(skb, 0, &ip6h, sizeof(ip6h)) < 0)
		return TC_ACT_OK;

	/* Only tag IPv6 */
	if (ip6h.version != 6)
		return TC_ACT_OK;

	/* Look up app_index from socket cookie */
	__u64 cookie = bpf_get_socket_cookie(skb);
	__u32 app_index = 0;
	__u32 *idx = bpf_map_lookup_elem(&socket_to_app, &cookie);
	if (idx)
		app_index = *idx;

	/* Read current epoch */
	__u8 epoch_tag = (__u8)(get_current_epoch() & 0xff);

	/* Encode: flow_label = app_index (20 bits), traffic_class = epoch_tag (8 bits)
	 *
	 * IPv6 header bytes 0-3:
	 *   byte 0: version(4) | tc_hi(4)
	 *   byte 1: tc_lo(4) | flow_hi(4)
	 *   byte 2-3: flow_lo(16)
	 *
	 * traffic_class = (tc_hi << 4) | tc_lo = epoch_tag
	 * flow_label = (flow_hi << 16) | flow_lo = app_index & 0xfffff
	 */
	__u32 flow20 = app_index & 0xfffff;
	__u8 tc = epoch_tag;

	__u8 hdr[4];
	hdr[0] = 0x60 | ((tc >> 4) & 0x0f);              /* version=6, tc_hi */
	hdr[1] = ((tc & 0x0f) << 4) | ((flow20 >> 16) & 0x0f); /* tc_lo, flow_hi */
	hdr[2] = (flow20 >> 8) & 0xff;                    /* flow_lo high byte */
	hdr[3] = flow20 & 0xff;                           /* flow_lo low byte */

	bpf_skb_store_bytes(skb, 0, hdr, sizeof(hdr), 0);

	return TC_ACT_OK;
}

/* --- TC ingress enforcer for WireGuard gateway (IPv6) --- */

/*
 * procroute_wg_enforce_ingress_v6: attached to wg0 tc ingress on the gateway.
 *
 * For each incoming IPv6 packet from a WireGuard peer:
 *   1. Parse IPv6 header safely via bpf_skb_load_bytes.
 *   2. Read app_index from flow_label (20 bits).
 *   3. Drop immediately if app_index == 0 (untagged).
 *   4. Read epoch_tag from traffic_class (8 bits).
 *   5. Extract dst_ip, dst_port, proto (nexthdr at offset 40).
 *   6. Check flow_cache_v6 fast path (epoch match + not expired).
 *   7. On miss: policy lookup using app_allow_v6 LPM trie.
 *   8. On allow: clear flow_label and traffic_class, update flow_cache_v6.
 *   9. On deny: emit gateway_deny_event_v6 to gw_deny_events_v6 ringbuf.
 */
SEC("tc")
int procroute_wg_enforce_ingress_v6(struct __sk_buff *skb)
{
	/* Read the IPv6 header (40 bytes) */
	struct ipv6hdr ip6h;
	if (bpf_skb_load_bytes(skb, 0, &ip6h, sizeof(ip6h)) < 0)
		return TC_ACT_OK; /* can't parse -> pass through */

	/* Only enforce IPv6 */
	if (ip6h.version != 6)
		return TC_ACT_OK;

	/* Extract protocol from nexthdr */
	__u8 proto = ip6h.nexthdr;

	/* Extract ports based on protocol (next header starts at offset 40) */
	__u16 src_port = 0;
	__u16 dst_port = 0;

	if (proto == PROTO_TCP) {
		struct tcphdr th;
		if (bpf_skb_load_bytes(skb, 40, &th, sizeof(th)) < 0)
			return TC_ACT_SHOT;
		src_port = bpf_ntohs(th.source);
		dst_port = bpf_ntohs(th.dest);
	} else if (proto == PROTO_UDP) {
		struct udphdr uh;
		if (bpf_skb_load_bytes(skb, 40, &uh, sizeof(uh)) < 0)
			return TC_ACT_SHOT;
		src_port = bpf_ntohs(uh.source);
		dst_port = bpf_ntohs(uh.dest);
	}
	/* For other protocols (ICMPv6, etc.), ports stay 0 */

	/* Check exempt ports before enforcing tags */
	if (bpf_map_lookup_elem(&exempt_ports, &dst_port))
		return TC_ACT_OK;

	/* Extract flow_label (20 bits) = app_index */
	__u32 app_index = ((__u32)(ip6h.flow_hi) << 16) |
			  (__u32)bpf_ntohs(ip6h.flow_lo);

	/* Drop untagged packets */
	if (app_index == 0)
		return TC_ACT_SHOT;

	/* Extract traffic_class (8 bits) = epoch_tag */
	__u8 epoch_tag = (ip6h.tc_hi << 4) | ip6h.tc_lo;

	
	__u32 fc_cfg_key = 0;
	__u8 *fc_enabled = bpf_map_lookup_elem(&flow_cache_config, &fc_cfg_key);
	int cache_on = fc_enabled ? (*fc_enabled != 0) : 1; /* default: enabled */

	
	struct flow_cache_key_v6 fkey = {};
	__builtin_memcpy(fkey.src_ip, ip6h.saddr, 16);
	__builtin_memcpy(fkey.dst_ip, ip6h.daddr, 16);
	fkey.src_port = bpf_htons(src_port);
	fkey.dst_port = bpf_htons(dst_port);
	fkey.proto    = proto;

	if (cache_on) {
		struct flow_cache_val *fval =
			bpf_map_lookup_elem(&flow_cache_v6, &fkey);
		if (fval) {
			__u64 now = bpf_ktime_get_ns();
			if (fval->epoch == epoch_tag &&
			    fval->app_index == app_index &&
			    (fval->expiry_ns == 0 || now < fval->expiry_ns)) {
				/* Cache hit -- increment stats, allow */
				__u32 hit_key = 0;
				__u64 *hit_cnt = bpf_map_lookup_elem(
					&flow_cache_stats, &hit_key);
				if (hit_cnt)
					__sync_fetch_and_add(hit_cnt, 1);
				goto allow_v6;
			}
		}
		/* Cache miss -- increment stats */
		__u32 miss_key = 1;
		__u64 *miss_cnt = bpf_map_lookup_elem(
			&flow_cache_stats, &miss_key);
		if (miss_cnt)
			__sync_fetch_and_add(miss_cnt, 1);
	}

	/* slow path */
	{
		/* Check if destination is an internal prefix */
		struct lpm_key_v6 ikey = { .prefixlen = 128 };
		__builtin_memcpy(ikey.addr, ip6h.daddr, 16);
		if (!bpf_map_lookup_elem(&internal_prefixes_v6, &ikey)) {
			/* Not internal -- allow without cache update */
			goto allow_v6;
		}

		/* Per-app LPM lookup */
		struct app_lpm_key_v6 akey = {
			.prefixlen = 32 + 128,
			.app_index = app_index,
		};
		__builtin_memcpy(akey.addr, ip6h.daddr, 16);

		struct allow_rule *rule =
			bpf_map_lookup_elem(&app_allow_v6, &akey);
		if (!rule) {
			goto deny_v6;
		}

		/* Port + protocol check */
		if (!check_port_proto(rule, dst_port, proto)) {
			goto deny_v6;
		}

		/* Update flow cache on allow (only if cache is enabled) */
		if (cache_on) {
			struct flow_cache_val new_fval = {
				.epoch     = epoch_tag,
				.app_index = app_index,
				.expiry_ns = bpf_ktime_get_ns() + FLOW_CACHE_TTL_NS,
			};
			bpf_map_update_elem(&flow_cache_v6, &fkey, &new_fval,
					    0 /* BPF_ANY */);
			/* Increment insert counter */
			__u32 ins_key = 2;
			__u64 *ins_cnt = bpf_map_lookup_elem(
				&flow_cache_stats, &ins_key);
			if (ins_cnt)
				__sync_fetch_and_add(ins_cnt, 1);
		}
	}

allow_v6:
	/* Clear flow_label and traffic_class -- write clean IPv6 version byte */
	{
		__u8 clean_hdr[4] = { 0x60, 0x00, 0x00, 0x00 };
		bpf_skb_store_bytes(skb, 0, clean_hdr, sizeof(clean_hdr), 0);
	}
	return TC_ACT_OK;

deny_v6:
	/* Emit gateway deny event v6 */
	{
		struct gateway_deny_event_v6 *evt;
		evt = bpf_ringbuf_reserve(&gw_deny_events_v6, sizeof(*evt), 0);
		if (evt) {
			evt->timestamp_ns = bpf_ktime_get_ns();
			__builtin_memcpy(evt->src_ip, ip6h.saddr, 16);
			__builtin_memcpy(evt->dst_ip, ip6h.daddr, 16);
			evt->src_port  = src_port;
			evt->dst_port  = dst_port;
			evt->app_index = app_index;
			evt->proto     = proto;
			bpf_ringbuf_submit(evt, 0);
		}
	}
	return TC_ACT_SHOT;
}

/* --- Tracepoint programs for binary hash verification --- */

/*
 * Tracepoint context for sched_process_exec / sched_process_exit.
 * We only need the first few fields; the kernel provides more.
 */
struct trace_event_raw_sched_process_template {
	__u64 __do_not_use__;  /* common fields */
	__u64 __do_not_use2__; /* padding */
	__u32 pid;             /* kernel pid (= userspace tgid) */
};

SEC("tracepoint/sched/sched_process_exec")
int procroute_exec(struct trace_event_raw_sched_process_template *ctx)
{
	__u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	__u64 cgid = bpf_get_current_cgroup_id();

	/* Is this cgroup managed by ProcRoute? */
	__u32 *app_idx = bpf_map_lookup_elem(&cgroup_to_app, &cgid);
	if (!app_idx)
		return 0;

	/* Does this app require hash verification? */
	if (!bpf_map_lookup_elem(&app_exec_hash, app_idx))
		return 0;

	/* Invalidate any prior verification for this tgid */
	bpf_map_delete_elem(&task_verified, &tgid);

	/* Emit exec event to userspace for hash verification */
	struct exec_event *evt;
	evt = bpf_ringbuf_reserve(&exec_events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	evt->timestamp_ns = bpf_ktime_get_ns();
	evt->cgroup_id = cgid;
	evt->tgid = tgid;
	evt->app_index = *app_idx;
	bpf_get_current_comm(evt->comm, sizeof(evt->comm));

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int procroute_exit(struct trace_event_raw_sched_process_template *ctx)
{
	__u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	bpf_map_delete_elem(&task_verified, &tgid);
	return 0;
}

LICENSE("GPL");

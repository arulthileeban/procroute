/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Byte-order macros for BPF programs.
 */
#ifndef __BPF_ENDIAN_H
#define __BPF_ENDIAN_H

#include "bpf_helpers.h"

/*
 * BPF target is always little-endian on x86_64 (our only target).
 * Network byte order is big-endian.
 */
#define ___bpf_swab16(x) ((__u16)(x) << 8 | (__u16)(x) >> 8)

#define ___bpf_swab32(x)                                                      \
	((__u32)(x) >> 24 | ((__u32)(x) & 0x00FF0000) >> 8 |                   \
	 ((__u32)(x) & 0x0000FF00) << 8 | (__u32)(x) << 24)

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define bpf_htons(x)                                                           \
	(__builtin_constant_p(x) ? ___bpf_swab16(x)                            \
				 : (__u16)__builtin_bswap16((__u16)(x)))
#define bpf_ntohs(x) bpf_htons(x)
#define bpf_htonl(x)                                                           \
	(__builtin_constant_p(x) ? ___bpf_swab32(x)                            \
				 : (__u32)__builtin_bswap32((__u32)(x)))
#define bpf_ntohl(x) bpf_htonl(x)
#else
#define bpf_htons(x) (x)
#define bpf_ntohs(x) (x)
#define bpf_htonl(x) (x)
#define bpf_ntohl(x) (x)
#endif

#endif /* __BPF_ENDIAN_H */

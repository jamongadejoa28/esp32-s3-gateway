/*
 * gw_ip4.h - IPv4 address/CIDR parsing and subnet arithmetic (pure C).
 *
 * Shared by store (cfg_validate: static IP sanity, AP/Ethernet overlap, allowlist syntax),
 * net (ip_filter, net_mgr) and snmp (trap targets). Lives in gw_core so store does not depend
 * on net. All uint32_t addresses are HOST byte order (a.b.c.d == a<<24|b<<16|c<<8|d).
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "gw_core/gw_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Strict dotted quad "a.b.c.d" (decimal, 0..255, no leading zeros except "0", no spaces). */
bool gw_ip4_parse(const char *s, uint32_t *out);

/** Format as dotted quad into out[GW_IP4_STR_SZ]. */
void gw_ip4_format(uint32_t ip, char out[GW_IP4_STR_SZ]);

/** True iff mask is contiguous ones followed by zeros (0.0.0.0 and 255.255.255.255 included). */
bool gw_ip4_mask_valid(uint32_t mask);

/** Prefix length of a valid mask (0..32), -1 if not contiguous. */
int gw_ip4_prefix_len(uint32_t mask);

/** Mask for a prefix length 0..32. */
uint32_t gw_ip4_mask_from_prefix(unsigned prefix);

/**
 * Parse "a.b.c.d/n" (n 0..32) or bare "a.b.c.d" (= /32). Rejects host bits set outside the
 * prefix (e.g. "10.0.0.1/8") so the stored allowlist is canonical.
 */
bool gw_cidr_parse(const char *s, uint32_t *net, uint32_t *mask);

/** Format "a.b.c.d/n" into out[GW_CIDR_STR_SZ]. */
void gw_cidr_format(uint32_t net, uint32_t mask, char out[GW_CIDR_STR_SZ]);

/** (ip & mask) == (net & mask). */
bool gw_ip4_in_net(uint32_t ip, uint32_t net, uint32_t mask);

/** True iff the two networks share at least one address. */
bool gw_ip4_nets_overlap(uint32_t net1, uint32_t mask1, uint32_t net2, uint32_t mask2);

/**
 * Usable unicast host address for interface config: not 0.0.0.0/8, 127/8, multicast/reserved
 * (>= 224.0.0.0), and (for prefixes <= /30) not the network or broadcast address of `mask`.
 */
bool gw_ip4_host_valid(uint32_t ip, uint32_t mask);

#ifdef __cplusplus
}
#endif

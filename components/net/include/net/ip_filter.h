/*
 * ip_filter.h - IP allowlist evaluation and Host-header check (pure C, host-tested). DESIGN.md §6:
 * <= GW_MAX_IP_ALLOW CIDRs enforced in httpd open_fn and the SNMP transport; an empty list allows
 * everyone; connections from the recovery AP are always exempt; loopback allowed.
 * All addresses host byte order.
 *
 * "From the recovery AP" means local address == AP address AND peer inside the AP subnet
 * (CFG_AP_IP/CFG_AP_MASK). The local address alone is not enough: lwIP accepts a packet for ANY of
 * its addresses on ANY interface (weak host model, ip4.c), so a LAN host could route 192.168.150.1
 * via the gateway's Ethernet address. The peer-subnet test makes a spoofed TCP handshake fail
 * (replies go out the AP); net additionally installs a strong-host LWIP_HOOK_IP4_INPUT (via
 * ESP_IDF_LWIP_HOOK_FILENAME, IDF 6.1 lwip_default_hooks.h) that drops packets addressed to the AP
 * address which did not arrive on the AP netif, closing the UDP/SNMP case as well.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "gw_core/gw_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t net[GW_MAX_IP_ALLOW];
    uint32_t mask[GW_MAX_IP_ALLOW];
    uint8_t n;
} ip_filter_t;

/** Load entries (net already masked). n > GW_MAX_IP_ALLOW is truncated. */
void ip_filter_set(ip_filter_t *f, const uint32_t *nets, const uint32_t *masks, size_t n);

/** True if the list is empty or ip is inside any entry. */
bool ip_filter_match(const ip_filter_t *f, uint32_t ip);

/**
 * Full decision: loopback peer on a loopback local address (both in 127/8) -> true; local_ip == ap_ip and gw_ip4_in_net(peer_ip, ap_ip, ap_mask)
 * (from the recovery AP) -> true; else ip_filter_match(peer_ip).
 */
bool ip_filter_allows(const ip_filter_t *f, uint32_t peer_ip, uint32_t local_ip, uint32_t ap_ip,
                      uint32_t ap_mask);

/**
 * Lock-out guard for PUT /config/security: true if applying `f` would reject `client_ip` that is not
 * from the recovery AP (via_ap as computed by ip_filter_allows' AP rule; the API then answers 422
 * field "ip_allow", code "lockout").
 */
bool ip_filter_would_lock_out(const ip_filter_t *f, uint32_t client_ip, bool via_ap);

/**
 * Host-header check (DNS-rebinding defence). host_hdr = HTTP Host value: "<name>" or
 * "<name>:<digits>". True iff <name> is the dotted quad of one of ips[0..n) (non-zero entries), or
 * equals hostname or hostname + ".local" (ASCII case-insensitive; hostname NULL/"" matches no
 * name). Anything else - other names, IPv6 literals, empty, trailing dot, bad port - is false.
 */
bool ip_filter_host_ok(const char *host_hdr, const uint32_t *ips, size_t n, const char *hostname);

#ifdef __cplusplus
}
#endif

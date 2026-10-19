/*
 * net_lwip_hooks.h - lwIP hook file injected into the lwip component by components/net/CMakeLists.txt
 * (ESP_IDF_LWIP_HOOK_FILENAME, included by IDF 6.1 port/include/lwip_default_hooks.h; see
 * docs/api-guides/lwip.rst "Customized lwIP Hooks"). Only lwip's own translation units see it.
 *
 * Strong-host rule for the recovery AP (DESIGN.md §6, ip_filter.h): lwIP accepts a packet for ANY
 * of its addresses on ANY interface (weak host model). A LAN host could therefore reach the AP
 * address 192.168.150.1 through the Ethernet interface and claim the allowlist exemption that is
 * reserved for AP clients. LWIP_HOOK_IP4_INPUT drops every IPv4 packet whose destination is the AP
 * address unless it arrived on the SoftAP netif (lwIP name "ap") and that netif owns the address.
 *
 * Martian filter (RFC 1122 3.2.1.3): a packet with a 127.0.0.0/8 SOURCE is dropped unless it came
 * in on lwIP's loopback netif ("lo"). lwIP's ip4_input only rejects broadcast/multicast sources, so
 * without this a LAN host could forge 127.0.0.1 as the source of a UDP datagram (SNMP) and claim
 * the loopback allowlist exemption. 0.0.0.0/8 sources stay allowed (DHCP clients on the AP).
 *
 * The hook is a static inline so it needs no link-time dependency from lwip back to net. It runs in
 * the TCP/IP thread for every received IPv4 packet: constant time, no locks, no allocation.
 */
#pragma once

#include "lwip/def.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Must equal CFG_AP_IP (store/config.h); checked by a static_assert in components/net/net_mgr.c. */
#define NET_HOOK_AP_IP_HOST 0xC0A89601UL /* 192.168.150.1 */
#define NET_HOOK_IP4_DEST_OFFSET 16      /* destination address in the IPv4 header */
#define NET_HOOK_IP4_SRC_OFFSET 12       /* source address in the IPv4 header */
#define NET_HOOK_IP4_MIN_HLEN 20
#define NET_HOOK_LOOPBACK_OCTET 127

static inline int net_lwip_ip4_input_hook(struct pbuf *p, struct netif *inp) {
    if (p == NULL || inp == NULL || p->len < NET_HOOK_IP4_MIN_HLEN) {
        return 0; /* lwIP drops malformed packets itself */
    }
    const u8_t *h = (const u8_t *)p->payload;
    if (h[NET_HOOK_IP4_SRC_OFFSET] == NET_HOOK_LOOPBACK_OCTET && !(inp->name[0] == 'l' && inp->name[1] == 'o')) {
        pbuf_free(p); /* martian: loopback source on a real interface */
        return 1;
    }
    const u32_t dest = ((u32_t)h[NET_HOOK_IP4_DEST_OFFSET] << 24) | ((u32_t)h[NET_HOOK_IP4_DEST_OFFSET + 1] << 16) |
                       ((u32_t)h[NET_HOOK_IP4_DEST_OFFSET + 2] << 8) | (u32_t)h[NET_HOOK_IP4_DEST_OFFSET + 3];
    if (dest != (u32_t)NET_HOOK_AP_IP_HOST) {
        return 0;
    }
    /* Accept only on the SoftAP netif itself: IDF's wlanif_init_ap() names it "ap" (esp_netif/lwip/
     * netif/wlanif.c; Ethernet is "en", STA "st"), AND it must own the AP address. Matching the address
     * alone is not enough: an Ethernet DHCP lease of 192.168.150.1 would otherwise pass. */
    if (inp->name[0] == 'a' && inp->name[1] == 'p' &&
        lwip_ntohl(ip4_addr_get_u32(netif_ip4_addr(inp))) == (u32_t)NET_HOOK_AP_IP_HOST) {
        return 0;
    }
    pbuf_free(p); /* consumed: the packet is the hook's responsibility */
    return 1;
}

#define LWIP_HOOK_IP4_INPUT(p, inp) net_lwip_ip4_input_hook((p), (inp))

#ifdef __cplusplus
}
#endif

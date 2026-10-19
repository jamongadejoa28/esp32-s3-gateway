/* IP allowlist + Host-header check (contract: net/ip_filter.h). Pure C, host-tested
 * (tests/test_net_pure.py). Self-contained on purpose (no gw_ip4.c dependency): this is the
 * security boundary of every HTTP/SNMP request. */
#include "net/ip_filter.h"

#include <string.h>

#define IP4_LOOPBACK_NET 0x7F000000u
#define IP4_LOOPBACK_MASK 0xFF000000u

void ip_filter_set(ip_filter_t *f, const uint32_t *nets, const uint32_t *masks, size_t n) {
    if (!f) {
        return;
    }
    memset(f, 0, sizeof(*f));
    if (!nets || !masks) {
        return;
    }
    if (n > GW_MAX_IP_ALLOW) {
        n = GW_MAX_IP_ALLOW;
    }
    for (size_t i = 0; i < n; i++) {
        f->mask[i] = masks[i];
        f->net[i] = nets[i] & masks[i];
    }
    f->n = (uint8_t)n;
}

bool ip_filter_match(const ip_filter_t *f, uint32_t ip) {
    if (!f || f->n == 0) {
        return true;
    }
    const size_t n = f->n > GW_MAX_IP_ALLOW ? GW_MAX_IP_ALLOW : f->n;
    for (size_t i = 0; i < n; i++) {
        if ((ip & f->mask[i]) == (f->net[i] & f->mask[i])) {
            return true;
        }
    }
    return false;
}

static bool from_ap(uint32_t peer_ip, uint32_t local_ip, uint32_t ap_ip, uint32_t ap_mask) {
    return ap_ip != 0 && local_ip == ap_ip && (peer_ip & ap_mask) == (ap_ip & ap_mask);
}

bool ip_filter_allows(const ip_filter_t *f, uint32_t peer_ip, uint32_t local_ip, uint32_t ap_ip,
                      uint32_t ap_mask) {
    /* Loopback exemption only for a real loopback flow: BOTH ends in 127/8. A datagram from a
     * spoofed 127.x source arriving on Ethernet/AP has a non-loopback local address (and is also
     * dropped by the lwIP martian filter in lwip_hooks/net_lwip_hooks.h). */
    if ((peer_ip & IP4_LOOPBACK_MASK) == IP4_LOOPBACK_NET && (local_ip & IP4_LOOPBACK_MASK) == IP4_LOOPBACK_NET) {
        return true;
    }
    if (from_ap(peer_ip, local_ip, ap_ip, ap_mask)) {
        return true;
    }
    return ip_filter_match(f, peer_ip);
}

bool ip_filter_would_lock_out(const ip_filter_t *f, uint32_t client_ip, bool via_ap) {
    if (via_ap || (client_ip & IP4_LOOPBACK_MASK) == IP4_LOOPBACK_NET) {
        return false;
    }
    return !ip_filter_match(f, client_ip);
}

/* Strict dotted quad of exactly len bytes: 4 decimal octets 0..255, no leading zeros, no signs. */
static bool parse_quad(const char *s, size_t len, uint32_t *out) {
    uint32_t ip = 0;
    size_t i = 0;
    for (int part = 0; part < 4; part++) {
        if (part > 0) {
            if (i >= len || s[i] != '.') {
                return false;
            }
            i++;
        }
        const size_t start = i;
        unsigned v = 0;
        while (i < len && s[i] >= '0' && s[i] <= '9' && i - start < 3) {
            v = v * 10 + (unsigned)(s[i] - '0');
            i++;
        }
        const size_t digits = i - start;
        if (digits == 0 || v > 255 || (digits > 1 && s[start] == '0')) {
            return false;
        }
        ip = (ip << 8) | v;
    }
    if (i != len) {
        return false;
    }
    *out = ip;
    return true;
}

static char lower(char c) {
    return (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
}

static bool eq_nocase(const char *a, size_t alen, const char *b, size_t blen) {
    if (alen != blen) {
        return false;
    }
    for (size_t i = 0; i < alen; i++) {
        if (lower(a[i]) != lower(b[i])) {
            return false;
        }
    }
    return true;
}

bool ip_filter_host_ok(const char *host_hdr, const uint32_t *ips, size_t n, const char *hostname) {
    if (!host_hdr || !host_hdr[0]) {
        return false;
    }
    /* Bounded scan: a Host value longer than any acceptable one is rejected outright. */
    enum { HOST_HDR_MAX = GW_HOSTNAME_MAX + 6 /* ".local" */ + 6 /* ":65535" */ };
    size_t len = 0;
    while (host_hdr[len]) {
        if (++len > HOST_HDR_MAX) {
            return false;
        }
    }
    if (host_hdr[0] == '[') {
        return false; /* IPv6 literal: the device is IPv4-only */
    }
    size_t name_len = len;
    const char *colon = memchr(host_hdr, ':', len);
    if (colon) {
        name_len = (size_t)(colon - host_hdr);
        const char *p = colon + 1;
        const size_t plen = len - name_len - 1;
        if (plen == 0 || plen > 5) {
            return false;
        }
        unsigned port = 0;
        for (size_t i = 0; i < plen; i++) {
            if (p[i] < '0' || p[i] > '9') {
                return false; /* also rejects a second ':' */
            }
            port = port * 10 + (unsigned)(p[i] - '0');
        }
        if (port == 0 || port > 65535) {
            return false;
        }
    }
    if (name_len == 0 || host_hdr[name_len - 1] == '.') {
        return false;
    }
    uint32_t ip;
    if (parse_quad(host_hdr, name_len, &ip)) {
        if (!ips || ip == 0) {
            return false;
        }
        for (size_t i = 0; i < n; i++) {
            if (ips[i] != 0 && ips[i] == ip) {
                return true;
            }
        }
        return false;
    }
    if (!hostname || !hostname[0]) {
        return false;
    }
    size_t hlen = 0;
    while (hostname[hlen]) {
        if (++hlen > GW_HOSTNAME_MAX) {
            return false;
        }
    }
    if (eq_nocase(host_hdr, name_len, hostname, hlen)) {
        return true;
    }
    static const char LOCAL[] = ".local";
    return name_len == hlen + sizeof(LOCAL) - 1 && eq_nocase(host_hdr, hlen, hostname, hlen) &&
           eq_nocase(host_hdr + hlen, sizeof(LOCAL) - 1, LOCAL, sizeof(LOCAL) - 1);
}

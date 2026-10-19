/*
 * gw_ip4.c - IPv4 address/CIDR parsing and subnet arithmetic (pure C, host-tested).
 * Contract: gw_core/gw_ip4.h. Addresses are host byte order.
 */
#include "gw_core/gw_ip4.h"

#include <stdio.h>

/* Parse one decimal octet at *ps (no sign, no leading zeros except "0"); advances *ps. */
static bool parse_octet(const char **ps, uint32_t *out) {
    const char *s = *ps;
    if (*s < '0' || *s > '9')
        return false;
    if (*s == '0' && s[1] >= '0' && s[1] <= '9')
        return false; /* leading zero */
    uint32_t v = 0;
    int n = 0;
    while (*s >= '0' && *s <= '9') {
        v = v * 10u + (uint32_t)(*s - '0');
        if (++n > 3 || v > 255u)
            return false;
        s++;
    }
    *out = v;
    *ps = s;
    return true;
}

/* Parse a dotted quad at *ps, stopping at the first char after the 4th octet. */
static bool parse_quad(const char **ps, uint32_t *out) {
    uint32_t ip = 0;
    for (int i = 0; i < 4; i++) {
        uint32_t o;
        if (!parse_octet(ps, &o))
            return false;
        ip = (ip << 8) | o;
        if (i < 3) {
            if (**ps != '.')
                return false;
            (*ps)++;
        }
    }
    *out = ip;
    return true;
}

bool gw_ip4_parse(const char *s, uint32_t *out) {
    if (!s || !out)
        return false;
    uint32_t ip;
    if (!parse_quad(&s, &ip) || *s != '\0')
        return false;
    *out = ip;
    return true;
}

void gw_ip4_format(uint32_t ip, char out[GW_IP4_STR_SZ]) {
    snprintf(out, GW_IP4_STR_SZ, "%u.%u.%u.%u", (unsigned)(ip >> 24) & 0xFFu, (unsigned)(ip >> 16) & 0xFFu,
             (unsigned)(ip >> 8) & 0xFFu, (unsigned)ip & 0xFFu);
}

bool gw_ip4_mask_valid(uint32_t mask) {
    uint32_t inv = ~mask;
    return (inv & (inv + 1u)) == 0; /* ~mask must be 2^k - 1 */
}

int gw_ip4_prefix_len(uint32_t mask) {
    if (!gw_ip4_mask_valid(mask))
        return -1;
    int n = 0;
    while (mask & 0x80000000u) {
        n++;
        mask <<= 1;
    }
    return n;
}

uint32_t gw_ip4_mask_from_prefix(unsigned prefix) {
    if (prefix == 0)
        return 0;
    if (prefix >= 32)
        return 0xFFFFFFFFu;
    return 0xFFFFFFFFu << (32u - prefix);
}

bool gw_cidr_parse(const char *s, uint32_t *net, uint32_t *mask) {
    if (!s || !net || !mask)
        return false;
    uint32_t ip;
    if (!parse_quad(&s, &ip))
        return false;
    unsigned prefix = 32;
    if (*s == '/') {
        s++;
        if (*s < '0' || *s > '9')
            return false;
        if (*s == '0' && s[1] != '\0')
            return false; /* "/01" */
        unsigned p = 0;
        int n = 0;
        while (*s >= '0' && *s <= '9') {
            p = p * 10u + (unsigned)(*s - '0');
            if (++n > 2)
                return false;
            s++;
        }
        if (p > 32)
            return false;
        prefix = p;
    }
    if (*s != '\0')
        return false;
    uint32_t m = gw_ip4_mask_from_prefix(prefix);
    if (ip & ~m)
        return false; /* host bits set: not canonical */
    *net = ip;
    *mask = m;
    return true;
}

void gw_cidr_format(uint32_t net, uint32_t mask, char out[GW_CIDR_STR_SZ]) {
    char ip[GW_IP4_STR_SZ];
    gw_ip4_format(net, ip);
    int p = gw_ip4_prefix_len(mask);
    unsigned prefix = p < 0 ? 32u : ((unsigned)p & 63u);
    int n = snprintf(out, GW_CIDR_STR_SZ, "%s/%u", ip, prefix);
    if (n < 0)
        out[0] = '\0';
}

bool gw_ip4_in_net(uint32_t ip, uint32_t net, uint32_t mask) {
    return (ip & mask) == (net & mask);
}

bool gw_ip4_nets_overlap(uint32_t net1, uint32_t mask1, uint32_t net2, uint32_t mask2) {
    /* Two prefixes overlap iff they agree on the bits of the shorter (wider) mask. */
    uint32_t m = mask1 & mask2;
    return (net1 & m) == (net2 & m);
}

bool gw_ip4_host_valid(uint32_t ip, uint32_t mask) {
    uint32_t first = ip >> 24;
    if (first == 0 || first == 127 || first >= 224)
        return false;
    if (!gw_ip4_mask_valid(mask))
        return false;
    int prefix = gw_ip4_prefix_len(mask);
    if (prefix <= 30) {
        uint32_t host = ip & ~mask;
        if (host == 0 || host == ~mask)
            return false; /* network or broadcast address */
    }
    return true;
}

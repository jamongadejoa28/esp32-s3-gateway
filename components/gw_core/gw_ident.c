/* Device identity strings (contract: gw_core/gw_ident.h). Pure C, host-tested (tests/test_gw_ident.py). */
#include "gw_core/gw_ident.h"

#include <stdio.h>

static const char HEX_UP[] = "0123456789ABCDEF";
static const char HEX_LO[] = "0123456789abcdef";

static void suffix_hex(const uint8_t mac[GW_MAC_LEN], const char *digits, char out[5]) {
    out[0] = digits[mac[4] >> 4];
    out[1] = digits[mac[4] & 0x0F];
    out[2] = digits[mac[5] >> 4];
    out[3] = digits[mac[5] & 0x0F];
    out[4] = '\0';
}

void gw_ident_suffix(const uint8_t mac[GW_MAC_LEN], char out[5]) {
    suffix_hex(mac, HEX_UP, out);
}

void gw_ident_hostname(const uint8_t mac[GW_MAC_LEN], char out[GW_HOSTNAME_SZ]) {
    char sfx[5];
    suffix_hex(mac, HEX_LO, sfx);
    snprintf(out, GW_HOSTNAME_SZ, "mestio-gw-%s", sfx);
}

void gw_ident_ssid(const uint8_t mac[GW_MAC_LEN], char out[GW_SSID_SZ]) {
    char sfx[5];
    suffix_hex(mac, HEX_UP, sfx);
    snprintf(out, GW_SSID_SZ, "MESTIO-GW-%s", sfx);
}

void gw_ident_ap_psk_format(const uint8_t rnd[GW_AP_PSK_RAND_LEN], char out[GW_PSK_SZ]) {
    static const char B32[] = "abcdefghijklmnopqrstuvwxyz234567";
    /* 80 bits = 16 groups of 5 bits, MSB first (RFC 4648 bit order). */
    size_t o = 0;
    unsigned acc = 0, bits = 0;
    unsigned emitted = 0;
    for (size_t i = 0; i < GW_AP_PSK_RAND_LEN; i++) {
        acc = (acc << 8) | rnd[i];
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            if (emitted && emitted % 4 == 0) {
                out[o++] = '-';
            }
            out[o++] = B32[(acc >> bits) & 0x1F];
            emitted++;
        }
        acc &= (1u << bits) - 1u; /* keep only the unconsumed bits */
    }
    out[o] = '\0';
}

size_t gw_ident_engine_id(uint32_t pen, const uint8_t mac[GW_MAC_LEN], uint8_t out[GW_ENGINE_ID_LEN]) {
    const uint32_t v = 0x80000000u | pen;
    out[0] = (uint8_t)(v >> 24);
    out[1] = (uint8_t)(v >> 16);
    out[2] = (uint8_t)(v >> 8);
    out[3] = (uint8_t)v;
    out[4] = 0x03; /* RFC 3411 format: MAC address */
    for (size_t i = 0; i < GW_MAC_LEN; i++) {
        out[5 + i] = mac[i];
    }
    return GW_ENGINE_ID_LEN;
}

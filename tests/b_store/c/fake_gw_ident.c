/*
 * fake_gw_ident.c - linked into stream B's host tests only while components/gw_core/gw_ident.c
 * (stream F) is not listed in GW_HOST_SOURCES_GW_CORE. Same formats as gw_core/gw_ident.h.
 */
#include <stdio.h>

#include "gw_core/gw_ident.h"

void gw_ident_suffix(const uint8_t mac[GW_MAC_LEN], char out[5]) {
    snprintf(out, 5, "%02X%02X", mac[4], mac[5]);
}

void gw_ident_hostname(const uint8_t mac[GW_MAC_LEN], char out[GW_HOSTNAME_SZ]) {
    snprintf(out, GW_HOSTNAME_SZ, "mestio-gw-%02x%02x", mac[4], mac[5]);
}

void gw_ident_ssid(const uint8_t mac[GW_MAC_LEN], char out[GW_SSID_SZ]) {
    snprintf(out, GW_SSID_SZ, "MESTIO-GW-%02X%02X", mac[4], mac[5]);
}

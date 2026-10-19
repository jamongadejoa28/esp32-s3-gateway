/*
 * gw_ident.h - device identity strings (pure C).
 *
 * Input MAC: the eFuse base MAC (esp_efuse_mac_get_default()), so every derived name is stable
 * regardless of which interface is up. MAC-derived values are PUBLIC identifiers (the MAC is visible
 * in the SSID, BSSID and on the LAN): never derive a secret from it. Pure functions; host-testable.
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

#include "gw_core/gw_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

#define GW_AP_PSK_RAND_LEN 10    /* random bytes behind a factory AP PSK (80 bits) */
#define GW_AP_PSK_DEFAULT_LEN 19 /* "xxxx-xxxx-xxxx-xxxx": 16 base32 chars + 3 dashes */
#define GW_ENGINE_ID_LEN 11      /* SNMP engine ID: 4 (enterprise|0x80000000) + 1 (format 3) + 6 (MAC) */

/** "XXXX": upper-case hex of mac[4], mac[5]. out >= 5 bytes. */
void gw_ident_suffix(const uint8_t mac[GW_MAC_LEN], char out[5]);

/** Default hostname "mestio-gw-xxxx" (lower-case suffix). */
void gw_ident_hostname(const uint8_t mac[GW_MAC_LEN], char out[GW_HOSTNAME_SZ]);

/** Default recovery AP SSID "MESTIO-GW-XXXX". */
void gw_ident_ssid(const uint8_t mac[GW_MAC_LEN], char out[GW_SSID_SZ]);

/**
 * Format a factory recovery-AP PSK from GW_AP_PSK_RAND_LEN random bytes: the 80 bits as 16
 * lower-case RFC 4648 base32 characters ("a-z2-7", MSB first) grouped 4-4-4-4 with '-'
 * (e.g. "mfrg-gzdf-mztw-q2lk" for "abcdefghij"). The PSK is NOT derived from the MAC (anything
 * MAC-derived is public). The random bytes come from gw_random() once per device lifetime; the
 * result is kept in NVS GW_NVS_NS_FACTORY/GW_NVS_KEY_AP_PSK by store (secrets.h). Pure.
 */
void gw_ident_ap_psk_format(const uint8_t rnd[GW_AP_PSK_RAND_LEN], char out[GW_PSK_SZ]);

/**
 * SNMP engine ID (RFC 3411 format 3 / MAC): BE32(0x80000000 | pen) || 0x03 || mac[6].
 * e.g. pen 32473 -> 80 00 7E D9 03 <mac>. Returns GW_ENGINE_ID_LEN.
 */
size_t gw_ident_engine_id(uint32_t pen, const uint8_t mac[GW_MAC_LEN], uint8_t out[GW_ENGINE_ID_LEN]);

#ifdef __cplusplus
}
#endif

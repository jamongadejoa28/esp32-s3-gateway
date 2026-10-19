/*
 * gw_defs.h - project-wide limits, string sizes and the web role enum (pure C, host-safe).
 *
 * Every fixed-size buffer that crosses a component boundary is sized from these constants.
 * "_MAX" = maximum number of characters, "_SZ" = buffer size including the terminating NUL.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* ---- Product identity ---- */
#define GW_PROJECT_NAME "mestio_gw" /* must equal esp_app_desc_t.project_name (OTA check) */
#define GW_PRODUCT_NAME "MESTIO Gateway"

/* ---- NVS keys shared across components ---- */
#define GW_NVS_NS "gw"              /* erased by factory reset */
#define GW_NVS_NS_FACTORY "gw_fact" /* survives factory reset */
#define GW_NVS_KEY_AP_PSK "ap_psk"  /* str: factory recovery-AP PSK, generated once (store/secrets.h) */
/* u32 boot counter = SNMP snmpEngineBoots, incremented by app_main at every boot. It lives in the
 * factory namespace so it never decreases across a factory reset while the engine ID stays the same
 * (RFC 3414 §2.2; DECISIONS.md "Contract issues — resolution"). Legacy GW_NVS_NS/"boots" values are
 * migrated by app_main (max of both). */
#define GW_NVS_NS_BOOTS GW_NVS_NS_FACTORY
#define GW_NVS_KEY_BOOTS "boots"

/* ---- Capacity limits (DESIGN.md §5–§10) ---- */
#define GW_MAX_DEVICES 4    /* MEX150 devices on the RS485 bus; dev index 0..GW_MAX_DEVICES-1 */
#define GW_MAX_USERS 4      /* web accounts */
#define GW_MAX_SESSIONS 8   /* concurrent web sessions (RAM table) */
#define GW_MAX_WS_CLIENTS 4 /* concurrent WebSocket clients */
#define GW_MAX_RULES 8      /* user threshold alarm rules */
#define GW_MAX_SEV_OVERRIDES 16
#define GW_MAX_TRAP_TARGETS 4 /* SNMP trap/inform destinations */
#define GW_MAX_SNMP_V3_USERS 2
#define GW_MAX_IP_ALLOW 8 /* CIDR entries in the IP allowlist */
#define GW_MAX_NTP_SERVERS 2

/* ---- String sizes ----
 * Every limit on a UTF-8 string is in BYTES (the buffers below), except GW_PASSWORD_MIN, which counts
 * characters (code points). JSON Schema maxLength (characters) is only an upper bound; the firmware
 * and the UI check bytes (docs/API.md §1). */
#define GW_USER_NAME_MAX 11 /* web user names; fits evlog_rec_t.user[12] with NUL */
#define GW_USER_NAME_SZ (GW_USER_NAME_MAX + 1)
#define GW_PASSWORD_MIN 10 /* characters (code points) */
#define GW_PASSWORD_MAX 64 /* UTF-8 bytes */
#define GW_PASSWORD_SZ (GW_PASSWORD_MAX + 1)
#define GW_DEV_NAME_SZ 24 /* mex_dev_cfg_t.name: at most 23 UTF-8 bytes */
#define GW_HOSTNAME_MAX 32
#define GW_HOSTNAME_SZ (GW_HOSTNAME_MAX + 1)
#define GW_SSID_MAX 32
#define GW_SSID_SZ (GW_SSID_MAX + 1)
#define GW_PSK_MIN 8
#define GW_PSK_MAX 63
#define GW_PSK_SZ (GW_PSK_MAX + 1)
#define GW_HOST_MAX 63 /* host names / addresses of NTP, syslog, trap targets */
#define GW_HOST_SZ (GW_HOST_MAX + 1)
#define GW_COMMUNITY_MAX 32 /* == SNMP_MAX_COMMUNITY_STR_LEN project define */
#define GW_COMMUNITY_SZ (GW_COMMUNITY_MAX + 1)
#define GW_SNMP_USER_MAX 32
#define GW_SNMP_USER_SZ (GW_SNMP_USER_MAX + 1)
#define GW_SNMP_PASS_MIN 8
#define GW_SNMP_PASS_MAX 64
#define GW_SNMP_PASS_SZ (GW_SNMP_PASS_MAX + 1)
#define GW_TEXT_MAX 63 /* site, location, contact, sysName ... */
#define GW_TEXT_SZ (GW_TEXT_MAX + 1)
#define GW_RULE_NAME_SZ 24 /* at most 23 UTF-8 bytes */
#define GW_TZ_SZ 48        /* POSIX TZ string, e.g. "KST-9" */
#define GW_VERSION_SZ 32   /* == sizeof(esp_app_desc_t.version) */
#define GW_CIDR_STR_SZ 19  /* "255.255.255.255/32" + NUL */
#define GW_IP4_STR_SZ 16   /* "255.255.255.255" + NUL */
#define GW_MAC_LEN 6

/* ---- Web roles (ordered: a higher value includes every lower privilege) ---- */
typedef enum {
    GW_ROLE_NONE = 0,     /* unauthenticated; only valid as a route's min_role */
    GW_ROLE_VIEWER = 1,   /* read-only */
    GW_ROLE_OPERATOR = 2, /* + setpoints, run/stop, alarm ack */
    GW_ROLE_ADMIN = 3,    /* + configuration, users, firmware, system */
} gw_role_t;

/** Wire name of a role ("viewer"/"operator"/"admin"; "none" for GW_ROLE_NONE). Never NULL. */
static inline const char *gw_role_name(gw_role_t r) {
    switch (r) {
    case GW_ROLE_VIEWER:
        return "viewer";
    case GW_ROLE_OPERATOR:
        return "operator";
    case GW_ROLE_ADMIN:
        return "admin";
    default:
        return "none";
    }
}

/** Parse a wire role name. Returns false (and leaves *out untouched) for anything else, incl. "none". */
static inline bool gw_role_from_name(const char *s, gw_role_t *out) {
    if (!s || !out)
        return false;
    if (!strcmp(s, "viewer"))
        *out = GW_ROLE_VIEWER;
    else if (!strcmp(s, "operator"))
        *out = GW_ROLE_OPERATOR;
    else if (!strcmp(s, "admin"))
        *out = GW_ROLE_ADMIN;
    else
        return false;
    return true;
}

/** Copy a NUL-terminated string into dst[cap], always terminating; truncates. */
static inline void gw_strlcpy(char *dst, const char *src, size_t cap) {
    if (!cap)
        return;
    size_t n = 0;
    while (src && n < cap - 1 && src[n])
        n++;
    if (n)
        memcpy(dst, src, n);
    dst[n] = '\0';
}

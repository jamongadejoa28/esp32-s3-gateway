/*
 * config.h - gateway configuration model (non-secret) and its in-RAM store.
 *
 * Pure part (host-testable, no IDF headers): types, defaults, validation, section metadata.
 * Device part (config.c, FreeRTOS mutex): config_load(), cfg_get*(), cfg_commit*().
 * JSON mapping lives in store/config_json.h. Secrets live in store/secrets.h and never here.
 *
 * File: /data/cfg/gateway.json  {"schema":1,"rev":N,"general":{},"network":{},"modbus":{},
 *       "alarms":{},"snmp":{},"time":{},"security":{},"notify":{}}  (DESIGN.md §7)
 *
 * Threading: the store keeps one gw_config_t behind a mutex. Readers get COPIES (never pointers).
 * cfg_commit*() validates, swaps, increments rev, posts GW_EVT_CONFIG_CHANGED and marks the file
 * dirty for the persist task; it never writes flash itself. All device functions are callable from
 * any task except ISRs; they do not block longer than the mutex hold time (memcpy).
 *
 * Addresses are uint32_t in host byte order (see gw_core/gw_ip4.h). Thresholds are raw integers at
 * the source register's scale (temp 30.5 °C -> 305).
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "gw_core/gw_defs.h"
#include "gw_core/gw_err.h"
#include "mex150/service.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CFG_SCHEMA_VERSION 1
#define CFG_ABS_SESSION_S (12u * 3600u) /* absolute session lifetime (not configurable) */

typedef enum {
    CFG_SEC_GENERAL = 0,
    CFG_SEC_NETWORK = 1,
    CFG_SEC_MODBUS = 2,
    CFG_SEC_ALARMS = 3, /* debounce, severity overrides and rules */
    CFG_SEC_SNMP = 4,
    CFG_SEC_TIME = 5,
    CFG_SEC_SECURITY = 6,
    CFG_SEC_NOTIFY = 7,
    CFG_SEC_COUNT,
    CFG_SEC_SECRETS = 0x7F, /* pseudo section used only in GW_EVT_CONFIG_CHANGED for secrets */
} cfg_section_t;

/* ---- general ---- */
typedef struct {
    char site[GW_TEXT_SZ];     /* default "" (UI shows hostname) */
    char location[GW_TEXT_SZ]; /* default "" */
    char contact[GW_TEXT_SZ];  /* default "" */
    char lang[3];              /* "ko" (default) | "en": default UI language */
} cfg_general_t;

/* ---- network ---- */
typedef enum { CFG_ETH_STATIC = 0, CFG_ETH_DHCP = 1 } cfg_eth_mode_t;

typedef struct {
    uint8_t mode;  /* cfg_eth_mode_t; default STATIC */
    uint32_t ip;   /* default 192.168.10.150 */
    uint32_t mask; /* default 255.255.255.0 */
    uint32_t gw;   /* default 192.168.10.1; 0 = none */
    uint32_t dns1; /* default 192.168.10.1; 0 = none */
    uint32_t dns2; /* default 0 */
} cfg_eth_t;

typedef struct {
    bool fallback;             /* auto-start AP when Ethernet has no link/IP; default true */
    char ssid[GW_SSID_SZ];     /* default "MESTIO-GW-XXXX" */
    uint8_t channel;           /* 1..13; default 6 */
    uint16_t idle_min;         /* stop AP this long after the last station left, 1..120; default 15 */
    uint16_t fallback_after_s; /* no link/IP this long after boot -> AP, 30..3600; default 120 */
} cfg_ap_t;                    /* AP address fixed 192.168.150.1/24; PSK lives in secrets */

typedef struct {
    cfg_eth_t eth;
    char hostname[GW_HOSTNAME_SZ]; /* RFC 1123 label, default "mestio-gw-xxxx" */
    cfg_ap_t ap;
} cfg_network_t;

#define CFG_AP_IP 0xC0A89601u   /* 192.168.150.1 */
#define CFG_AP_MASK 0xFFFFFF00u /* /24 */

/* ---- modbus ---- */
typedef struct {
    mex_port_cfg_t port;
    mex_dev_cfg_t devices[GW_MAX_DEVICES]; /* default: 1 device {id 0, slave 1, enabled, "MEX150"} */
    uint8_t n_devices;                     /* 1..GW_MAX_DEVICES */
} cfg_modbus_t;

/* ---- alarms ---- */
typedef enum { CFG_OP_GT = 0, CFG_OP_LT = 1 } cfg_rule_op_t;

/**
 * User threshold rule, evaluated on 1 Hz samples (alarm engine). For GT: raise when v > thr has
 * held for delay_s; clear when v <= thr - hyst. LT mirrored. Offline device -> state frozen.
 */
typedef struct {
    uint8_t id; /* 1..GW_MAX_RULES, unique; maps to alarm "rule_<id>" */
    char name[GW_RULE_NAME_SZ];
    bool enabled;
    uint8_t dev;      /* device index; default 0 */
    uint16_t addr;    /* source REG address: temp=40036, hum=40037, cur=40011, or any REG row */
    uint8_t op;       /* cfg_rule_op_t */
    int32_t thr;      /* raw at the source register's scale */
    int32_t hyst;     /* raw, >= 0 */
    uint16_t delay_s; /* on-delay 0..3600 */
    uint8_t sev;      /* alm_sev_t 1..3 */
} cfg_rule_t;

typedef struct {
    uint16_t code; /* alarm catalog code */
    uint8_t sev;   /* alm_sev_t 0..3 */
} cfg_sev_override_t;

typedef struct {
    uint8_t debounce_raise; /* consecutive polls, 1..10; default 2 */
    uint8_t debounce_clear; /* consecutive polls, 1..10; default 3 */
    cfg_sev_override_t sev_override[GW_MAX_SEV_OVERRIDES];
    uint8_t n_sev_override;
    cfg_rule_t rules[GW_MAX_RULES];
    uint8_t n_rules;
} cfg_alarms_t;

/* ---- snmp (non-secret part) ---- */
typedef enum { CFG_SNMP_RO = 0, CFG_SNMP_RW = 1 } cfg_snmp_access_t;
typedef enum { CFG_SNMP_V1 = 0, CFG_SNMP_V2C = 1 } cfg_snmp_version_t;

typedef struct {
    char name[GW_SNMP_USER_SZ]; /* slot 0 default "gwmonitor" (RO), slot 1 "gwadmin" (RW) */
    uint8_t access;             /* cfg_snmp_access_t */
    bool enabled;               /* default true; effective only once keys are set */
} cfg_snmp_v3user_t;            /* always authPriv HMAC-SHA-96 + AES-128-CFB */

/** Trap target. Its identity (for the secret community, see cfg_trap_remap) is (host, port). */
typedef struct {
    bool enabled;
    char host[GW_HOST_SZ]; /* IPv4 dotted quad (no DNS for traps) */
    uint16_t port;         /* default 162; sent via snmp_transport_set_trap_port() */
    uint8_t version;       /* cfg_snmp_version_t; default V2C */
    bool inform;           /* v2c only */
} cfg_trap_t;

typedef struct {
    bool enabled; /* agent answers requests; default false */
    bool v1;      /* default false; true requires a non-empty RO community (cfg_snmp_check_secrets) */
    bool v2c;     /* default false; true requires a non-empty RO community (cfg_snmp_check_secrets) */
    bool v3;      /* default true (users still need keys, see snmp_gw.h USM contract) */
    cfg_snmp_v3user_t users[GW_MAX_SNMP_V3_USERS]; /* fixed slots */
    cfg_trap_t traps[GW_MAX_TRAP_TARGETS];
    uint8_t n_traps;
    bool auth_traps;               /* send authenticationFailure traps; default false */
    char sys_name[GW_TEXT_SZ];     /* default "" -> hostname */
    char sys_contact[GW_TEXT_SZ];  /* default "" */
    char sys_location[GW_TEXT_SZ]; /* default "" */
} cfg_snmp_t;

/* ---- time ---- */
typedef struct {
    bool ntp_enabled;                             /* default false */
    char servers[GW_MAX_NTP_SERVERS][GW_HOST_SZ]; /* default pool.ntp.org, time.google.com */
    uint16_t interval_min;                        /* 15..1440; default 60 */
    char tz[GW_TZ_SZ];                            /* POSIX TZ; default "KST-9" */
} cfg_time_t;

/* ---- security ---- */
typedef struct {
    uint32_t net, mask;
} cfg_cidr_t;

typedef struct {
    uint16_t idle_min; /* 5..120; default 15 */
    uint8_t max_fail;  /* failures within 5 min before lockout, 3..10; default 5 */
    uint8_t lock_min;  /* first lock duration, 1..30; doubles per lock up to 30; default 5 */
    cfg_cidr_t ip_allow[GW_MAX_IP_ALLOW]; /* empty = allow all; AP interface always exempt */
    uint8_t n_ip_allow;
    bool svc_snmp;   /* master switch: SNMP runs only if this AND snmp.enabled; default true */
    bool svc_syslog; /* master switch: syslog sent only if this AND notify.syslog_enabled */
} cfg_security_t;

/* ---- notify ---- */
typedef struct {
    bool syslog_enabled;   /* default false */
    char host[GW_HOST_SZ]; /* IPv4 or hostname */
    uint16_t port;         /* default 514 */
    uint8_t facility;      /* 0..23; default 16 (local0) */
    uint8_t min_sev;       /* syslog severity 0..7; send messages with severity <= min_sev; default 5 */
} cfg_notify_t;

/** Complete configuration (~2 KB). */
typedef struct {
    uint16_t schema; /* CFG_SCHEMA_VERSION after load/migrate */
    uint32_t rev;    /* +1 per successful commit; persisted */
    cfg_general_t general;
    cfg_network_t network;
    cfg_modbus_t modbus;
    cfg_alarms_t alarms;
    cfg_snmp_t snmp;
    cfg_time_t time;
    cfg_security_t security;
    cfg_notify_t notify;
} gw_config_t;

/** Validation error: `field` is a dotted path relative to the document root, e.g.
 * "network.eth.ip", "modbus.devices[1].slave", "alarms.rules[0].thr". `code` is one of:
 * "required","type","range","format","length","duplicate","overlap","unknown_register",
 * "unknown_field","too_many","unsupported_schema". */
typedef struct {
    char field[48];
    char code[24];
} cfg_verr_t;

/** Read-back flags for write-only secrets ("..._set": true), filled from secrets (sec_flags()). */
typedef struct {
    bool ap_psk_set;                         /* always true (a factory PSK exists) */
    bool snmp_ro_set;                        /* RO community non-empty */
    bool snmp_rw_set;                        /* RW community non-empty (SET via community enabled) */
    bool v3_keys_set[GW_MAX_SNMP_V3_USERS];  /* localized keys stored */
    bool trap_comm_set[GW_MAX_TRAP_TARGETS]; /* community of slot i differs from SEC_DEFAULT_TRAP */
} cfg_secret_flags_t;

/** Write-only secret inputs extracted from a REST PUT body (has_* = field present). Wipe after use. */
typedef struct {
    bool has_ap_psk;
    char ap_psk[GW_PSK_SZ]; /* 8..63 printable ASCII */
    bool has_snmp_ro, has_snmp_rw;
    char snmp_ro[GW_COMMUNITY_SZ]; /* "" allowed for rw (= SET disabled) */
    char snmp_rw[GW_COMMUNITY_SZ];
    struct {
        bool has_auth, has_priv;
        char auth_pass[GW_SNMP_PASS_SZ]; /* 8..64 */
        char priv_pass[GW_SNMP_PASS_SZ];
    } v3[GW_MAX_SNMP_V3_USERS];
    struct {
        bool has;
        char community[GW_COMMUNITY_SZ];
    } trap[GW_MAX_TRAP_TARGETS];
    /* Trap-community remap, valid when has_traps (the body replaced "traps"): new slot i takes
     * trap[i].community if trap[i].has, else the stored community of old slot trap_from[i]
     * (>= 0), else SEC_DEFAULT_TRAP (-1). Filled by cfg_section_from_json via cfg_trap_remap();
     * applied with sec_trap_remap() inside secrets_modify(). */
    bool has_traps;
    int8_t trap_from[GW_MAX_TRAP_TARGETS];
} cfg_secret_input_t;

/* ======================= Pure functions ======================= */

/** Factory defaults (DESIGN.md §5). mac = eFuse base MAC (hostname/SSID suffix). */
void cfg_defaults(gw_config_t *c, const uint8_t mac[GW_MAC_LEN]);

/** Defaults of one section into sec (size cfg_section_size(s)). */
void cfg_section_defaults(cfg_section_t s, void *sec, const uint8_t mac[GW_MAC_LEN]);

/**
 * Validate a complete configuration including cross-field rules:
 * static ETH host valid & gw in subnet; ETH subnet must not overlap 192.168.150.0/24 (AP);
 * unique device ids/slaves; rule addr is a readable REG row, rule dev exists, thr within the
 * register's min..max; unique rule ids; overrides reference catalog codes that are not rule_*
 * (via the hook installed with cfg_set_alarm_catalog(); without a catalog every override is
 * rejected); trap hosts are IPv4; strings valid UTF-8 and within their BYTE limits (gw_defs.h).
 * Returns true if valid; else false with *err (optional) describing the FIRST problem.
 */
bool cfg_validate(const gw_config_t *c, cfg_verr_t *err);

/** cfg_validate() of `base` with section s replaced by `sec` (no mutation of base). */
bool cfg_validate_with(const gw_config_t *base, cfg_section_t s, const void *sec, cfg_verr_t *err);

/**
 * Alarm catalog access for store, which cannot depend on alarm (alarm REQUIRES store). Used to map
 * sev_override keys (JSON: alarm id string, RAM: catalog code) and to validate them.
 */
typedef struct {
    /** id -> code; false for unknown ids and for rule_* ids (rule severities come from the rules). */
    bool (*code_from_id)(const char *id, uint16_t *code);
    /** code -> id, or NULL when the code is not an overridable catalog entry. */
    const char *(*id_from_code)(uint16_t code);
} cfg_alarm_catalog_t;

/**
 * Install the catalog hooks (alarm.h provides alm_cfg_catalog). app_main calls it once at boot
 * before config_load(); host tests install their own. `cat` must stay valid forever. Without a
 * catalog (NULL, default) JSON sev_override members are rejected ("unknown_field") and
 * cfg_validate() rejects any override.
 */
void cfg_set_alarm_catalog(const cfg_alarm_catalog_t *cat);

/**
 * Trap-community remap for a replaced trap list: from[i] = index j of the old target with the same
 * (host, port) as new target i (first unused match), or -1 when target i is new or changed. Slots
 * >= nw->n_traps are set to -1. Used for PUT /config/snmp (via cfg_section_from_json) and config
 * import, so a stored community never follows a different host.
 */
void cfg_trap_remap(const cfg_snmp_t *old, const cfg_snmp_t *nw, int8_t from[GW_MAX_TRAP_TARGETS]);

/**
 * SNMP checks that need the secrets: v1 or v2c enabled requires a non-empty RO community
 * (`after` = flags as they will be after the change). Fails with field "snmp.ro", code "required".
 * Called by PUT /config/snmp and config import before committing.
 */
bool cfg_snmp_check_secrets(const cfg_snmp_t *s, const cfg_secret_flags_t *after, cfg_verr_t *err);

/** Section wire name ("general".."notify", "secrets" for CFG_SEC_SECRETS) or NULL. */
const char *cfg_section_name(cfg_section_t s);
/** Parse a wire name; false if unknown. */
bool cfg_section_from_name(const char *name, cfg_section_t *out);
/** sizeof the section struct (0 for invalid s). */
size_t cfg_section_size(cfg_section_t s);
/** Pointer to section s inside c (NULL for invalid s). */
void *cfg_section_ptr(gw_config_t *c, cfg_section_t s);
const void *cfg_section_cptr(const gw_config_t *c, cfg_section_t s);

/* ======================= Device store (config.c) ======================= */

/**
 * Load /data/cfg/gateway.json trying X, X.tmp, X.bak (each must parse, migrate and validate);
 * otherwise defaults (and schedule a write). Missing fields come from defaults; unknown ignored.
 * Must run after fs_mount() and before any cfg_get*. Returns ESP_OK in all non-fatal cases
 * (source used is logged); ESP_ERR_NO_MEM only on allocation failure.
 */
esp_err_t config_load(void);

/** Copy the whole configuration. */
void cfg_get(gw_config_t *out);

/** Copy one section; out_size must equal cfg_section_size(s) (ESP_ERR_INVALID_SIZE otherwise). */
esp_err_t cfg_get_section(cfg_section_t s, void *out, size_t out_size);

/** Current revision. */
uint32_t cfg_rev(void);

/**
 * Validate (cfg_validate_with), swap in RAM, rev++, post GW_EVT_CONFIG_CHANGED{s, rev, by},
 * mark the config file dirty (persist). If the section is byte-identical to the current one,
 * returns ESP_OK without bumping rev or posting.
 * @return ESP_OK, ESP_ERR_INVALID_ARG (validation failed, *err filled), ESP_ERR_INVALID_SIZE,
 *         ESP_ERR_INVALID_STATE (after config_factory_reset()).
 */
esp_err_t cfg_commit(cfg_section_t s, const void *sec, size_t size, const char *by, cfg_verr_t *err);

/**
 * Replace everything (config import). Validates the whole document; posts one CONFIG_CHANGED per
 * changed section. rev = max(current, c->rev) + 1.
 */
esp_err_t cfg_commit_all(const gw_config_t *c, const char *by, cfg_verr_t *err);

/** Serialized current config for persist (internal to store; exposed for config export/tests). */
esp_err_t cfg_snapshot_json(char **out, size_t *len); /* caller free()s */

/**
 * Factory reset of the configuration (sysmgr sys_factory_reset): replace the RAM config by
 * cfg_defaults() (keeping the current network section when keep_network), mark the config file
 * dirty so the persist task rewrites it atomically from the new RAM state, and freeze the store:
 * every later cfg_commit*() returns ESP_ERR_INVALID_STATE until reboot. Posts no CONFIG_CHANGED.
 * Returns once the write is queued; the caller then runs persist_flush() and reboots.
 */
esp_err_t config_factory_reset(bool keep_network);

#ifdef __cplusplus
}
#endif

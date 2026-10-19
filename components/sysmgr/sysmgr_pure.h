/*
 * sysmgr_pure.h - pure logic of the sysmgr component (no IDF headers; host-tested in
 * tests/test_sysmgr_pure.py): firmware version comparison / OTA image acceptance, build-date
 * formatting, RFC 5424 syslog formatting + rate limiting + severity mapping, status LED policy.
 * Private to sysmgr.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "gw_core/gw_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------- firmware versions (ota_version.c) ---------------- */

#define SYS_VER_PRE_SZ 32

/** Semantic version "MAJOR.MINOR.PATCH[-PRERELEASE][+BUILD]", optional leading 'v'. */
typedef struct {
    uint32_t major, minor, patch;
    char pre[SYS_VER_PRE_SZ]; /* "" for a release; build metadata is ignored */
} sys_ver_t;

/** Strict parse (SemVer 2.0.0: numeric parts without leading zeros, prerelease identifiers
 * [0-9A-Za-z-] dot-separated, numeric identifiers without leading zeros). */
bool sys_ver_parse(const char *s, sys_ver_t *out);

/** SemVer precedence: <0, 0, >0. A release ranks above its prereleases. */
int sys_ver_cmp(const sys_ver_t *a, const sys_ver_t *b);

/**
 * OTA image acceptance (sysmgr.h sys_ota_end): project_name must equal expect_project; the new
 * version must parse and be >= the running one unless allow_downgrade. A running version that does
 * not parse (development build) accepts any valid new version.
 * @return ESP_OK or ESP_ERR_INVALID_VERSION.
 */
esp_err_t sys_ota_check_image(const char *project_name, const char *new_version, const char *expect_project,
                              const char *running_version, bool allow_downgrade);

/** "Oct 19 2026" + "10:12:03" (esp_app_desc_t date/time, __DATE__/__TIME__) -> "2026-10-19 10:12:03".
 * Returns false (out = "") if the input is malformed. out >= 20 bytes. */
bool sys_build_date_iso(const char *date, const char *time, char *out, size_t cap);

/* ---------------- syslog (syslog_fmt.c) ---------------- */

#define SYSLOG_MAX_LINE 480 /* RFC 5426: every receiver must accept 480 octets */
#define SYSLOG_APP_NAME "mestio-gw"

/**
 * RFC 5424 line: "<PRI>1 TIMESTAMP HOSTNAME APP-NAME - MSGID - MSG".
 * TIMESTAMP is "YYYY-MM-DDTHH:MM:SS.mmmZ" or "-" when wall_ms <= 0; HOSTNAME/APP-NAME/MSGID are
 * printable US-ASCII (others replaced by '_', empty -> "-", truncated to the RFC field limits);
 * MSG control characters become ' '; MSG gets the UTF-8 BOM only when it contains non-ASCII bytes;
 * the line is truncated to min(cap - 1, SYSLOG_MAX_LINE) bytes on a UTF-8 boundary.
 * facility 0..23 and severity 0..7 (clamped). Returns the length (without NUL), 0 if cap < 2.
 */
size_t syslog_format(char *out, size_t cap, uint8_t facility, uint8_t severity, int64_t wall_ms,
                     const char *hostname, const char *app, const char *msgid, const char *msg);

/** Token bucket: `rate` tokens per second, at most `burst`. */
typedef struct {
    uint32_t milli_tokens; /* tokens x 1000 */
    uint32_t last_ms;
    bool primed;
    uint32_t dropped; /* refused since the last syslog_rl_take_dropped() */
} syslog_rl_t;

/** Take one token at now_ms; false (and dropped++) when the bucket is empty. */
bool syslog_rl_take(syslog_rl_t *rl, uint32_t now_ms, uint32_t rate, uint32_t burst);

/** Return and reset the dropped counter. */
uint32_t syslog_rl_take_dropped(syslog_rl_t *rl);

/** Syslog severity of an alarm transition (DECISIONS.md CONTRACTS min_sev): raise critical 2,
 * major 3, minor 4, info 5; clear and ack 5. type = gw_alarm_type_t, sev = alm_sev_t. */
uint8_t syslog_alarm_severity(uint8_t type, uint8_t sev);

/* ---------------- status LED policy (led_policy.c) ---------------- */

typedef struct {
    bool reset_armed;    /* BOOT held >= 10 s, or a factory reset is executing */
    bool ap_armed;       /* BOOT held 3..8 s */
    bool booting;        /* boot grace: not all required heartbeats seen yet */
    bool ota;            /* firmware upload in progress */
    bool fault;          /* a required heartbeat is stale after boot */
    uint16_t critical;   /* active critical alarms */
    uint16_t alarms;     /* active major + minor alarms */
    bool comm_lost;      /* an enabled device is offline */
    bool ap_active;      /* recovery AP running */
    bool net_ok;         /* Ethernet has an IPv4 address */
} sys_led_inputs_t;

/** board_led_t to show: RESET_ARMED > AP_ARMED > BOOT > OTA > FAULT > CRITICAL > ALARM > COMM_LOST
 * > AP > NO_NET > OK. */
uint8_t sys_led_select(const sys_led_inputs_t *in);

/* ---------------- health reboot policy (led_policy.c) ---------------- */

typedef struct {
    uint32_t mask;     /* last stale mask seen after boot */
    bool stale;        /* mask != 0 */
    uint64_t since_ms; /* uptime when the mask left 0 (valid while stale) */
} sys_stale_track_t;

/** Record a stale-heartbeat sample. since_ms is set only when the mask leaves 0 and is cleared only
 * when it returns to 0, so a second heartbeat going stale (or the mask moving between non-zero
 * values) never restarts the countdown. Returns true when the mask changed (log/evlog it). */
bool sys_stale_update(sys_stale_track_t *t, uint32_t stale_mask, uint64_t up_ms);

/** Health reboot due: `armed` (boot grace over; for a PENDING_VERIFY image the separate
 * not-yet-healthy limit applies instead), some required heartbeat stale for >= limit_ms, and fewer
 * than max_reboots consecutive health reboots already happened without a healthy period. */
bool sys_health_reboot_due(const sys_stale_track_t *t, bool armed, uint64_t up_ms, uint64_t limit_ms,
                           uint32_t prior_reboots, uint32_t max_reboots);

#ifdef __cplusplus
}
#endif

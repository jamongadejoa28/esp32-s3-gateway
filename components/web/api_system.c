/* System endpoints (docs/API.md §4.3, §4.10, §4.12): info, live network status, firmware info and
 * rollback, reboot, factory reset, logs, core dump summary. Reboots/resets go through sysmgr. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "auth/auth.h"
#include "esp_log.h"
#include "gw_core/gw_events.h"
#include "gw_core/gw_ip4.h"
#include "gw_core/gw_time.h"
#include "net/net.h"
#include "store/config.h"
#include "store/eventlog.h"
#include "store/fs.h"
#include "sysmgr/sysmgr.h"
#include "web/ws_hub.h"
#include "web_priv.h"

static const char *TAG = "api_sys";

#define REBOOT_DELAY_MS 2000u

static void mac_str(const uint8_t mac[GW_MAC_LEN], char out[18]) {
    snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void kip(gw_jw_t *w, const char *key, uint32_t ip) {
    char s[GW_IP4_STR_SZ];
    if (ip) {
        gw_ip4_format(ip, s);
    } else {
        s[0] = '\0';
    }
    gw_jw_kstr(w, key, s);
}

static esp_err_t send_reboot_in(web_ctx_t *c, uint32_t ms) {
    char body[32];
    int n = snprintf(body, sizeof(body), "{\"reboot_in_s\":%u}", (unsigned)((ms + 999u) / 1000u));
    return web_send_json(c, 202, body, (size_t)n);
}

/* ---------------------------------------------------------------- info / network */

esp_err_t h_system_info(web_ctx_t *c) {
    sys_info_t *si = malloc(sizeof(*si));
    if (!si) {
        return web_send_error(c, 503, WEB_E_UNAVAILABLE, NULL, NULL);
    }
    sys_get_info(si);
    net_status_t ns;
    net_get_status(&ns);
    size_t fs_total = 0, fs_used = 0;
    if (fs_info(&fs_total, &fs_used) != ESP_OK) {
        fs_total = fs_used = 0;
    }
    char mac[18];
    mac_str(si->mac, mac);
    char buf[640];
    gw_jw_t w;
    gw_jw_init_fixed(&w, buf, sizeof(buf));
    gw_jw_obj_open(&w);
    gw_jw_kstr(&w, "fw", si->fw);
    gw_jw_kstr(&w, "build", si->build);
    gw_jw_kstr(&w, "idf", si->idf);
    gw_jw_kstr(&w, "mac", mac);
    gw_jw_kstr(&w, "hostname", ns.hostname);
    gw_jw_kuint(&w, "uptime_s", si->uptime_s);
    gw_jw_kbool(&w, "time_valid", gw_time_valid());
    gw_jw_key(&w, "time_ms");
    web_json_epoch_ms(&w, gw_time_wall_ms());
    gw_jw_kobj(&w, "heap");
    gw_jw_kuint(&w, "int_free", si->heap_int_free);
    gw_jw_kuint(&w, "int_min", si->heap_int_min);
    gw_jw_kuint(&w, "psram_free", si->psram_free);
    gw_jw_obj_close(&w);
    gw_jw_kobj(&w, "part");
    gw_jw_kstr(&w, "running", si->part_running);
    gw_jw_kstr(&w, "state", si->part_state);
    gw_jw_obj_close(&w);
    gw_jw_kobj(&w, "diag");
    gw_jw_kuint(&w, "reset_reason", si->reset_reason);
    gw_jw_kuint(&w, "boot_count", si->boot_count);
    gw_jw_kuint(&w, "evt_dropped", si->evt_dropped);
    gw_jw_kuint(&w, "hb_stale", si->hb_stale);
    gw_jw_kuint(&w, "init_faults", si->init_faults);
    gw_jw_kuint(&w, "ws_clients", ws_hub_client_count());
    gw_jw_kobj(&w, "fs");
    gw_jw_kuint(&w, "total", fs_total);
    gw_jw_kuint(&w, "used", fs_used);
    gw_jw_obj_close(&w);
    gw_jw_obj_close(&w);
    gw_jw_obj_close(&w);
    free(si);
    return web_send_jw(c, 200, &w);
}

static const char *ap_reason(uint8_t r) {
    switch (r) {
    case NET_AP_REASON_BUTTON:
        return "button";
    case NET_AP_REASON_NO_LINK:
        return "no_link";
    case NET_AP_REASON_CONSOLE:
        return "console";
    default:
        return "none";
    }
}

esp_err_t h_system_network(web_ctx_t *c) {
    net_status_t ns;
    net_get_status(&ns);
    cfg_time_t tm;
    bool ntp = cfg_get_section(CFG_SEC_TIME, &tm, sizeof(tm)) == ESP_OK && tm.ntp_enabled;
    char mac[18];
    mac_str(ns.eth_mac, mac);
    char buf[640];
    gw_jw_t w;
    gw_jw_init_fixed(&w, buf, sizeof(buf));
    gw_jw_obj_open(&w);
    gw_jw_kobj(&w, "eth");
    gw_jw_kbool(&w, "link", ns.eth_link);
    gw_jw_kbool(&w, "has_ip", ns.eth_has_ip);
    gw_jw_kstr(&w, "mode", ns.eth_mode == CFG_ETH_DHCP ? "dhcp" : "static");
    kip(&w, "ip", ns.eth_has_ip ? ns.ip : 0);
    kip(&w, "mask", ns.eth_has_ip ? ns.mask : 0);
    kip(&w, "gw", ns.gw);
    kip(&w, "dns1", ns.dns1);
    kip(&w, "dns2", ns.dns2);
    gw_jw_kstr(&w, "mac", mac);
    gw_jw_kuint(&w, "link_changes", ns.link_changes);
    gw_jw_obj_close(&w);
    gw_jw_kobj(&w, "ap");
    gw_jw_kbool(&w, "active", ns.ap_active);
    gw_jw_kstr(&w, "reason", ns.ap_active ? ap_reason(ns.ap_reason) : "none");
    gw_jw_kuint(&w, "clients", ns.ap_clients > NET_AP_MAX_CLIENTS ? NET_AP_MAX_CLIENTS : ns.ap_clients);
    gw_jw_kstr(&w, "ssid", ns.ap_ssid);
    kip(&w, "ip", ns.ap_active ? ns.ap_ip : 0);
    gw_jw_kuint(&w, "off_in_s", ns.ap_off_in_s);
    gw_jw_obj_close(&w);
    gw_jw_key(&w, "provisional");
    if (ns.prov == NET_PROV_APPLY_PENDING || ns.prov == NET_PROV_AWAIT_CONFIRM) {
        gw_jw_obj_open(&w);
        gw_jw_kstr(&w, "state", ns.prov == NET_PROV_APPLY_PENDING ? "apply_pending" : "await_confirm");
        gw_jw_kuint(&w, "left_s", ns.prov_left_s);
        gw_jw_obj_close(&w);
    } else {
        gw_jw_null(&w);
    }
    gw_jw_kobj(&w, "sntp");
    gw_jw_kbool(&w, "enabled", ntp);
    gw_jw_kbool(&w, "synced", ns.sntp_synced);
    gw_jw_key(&w, "last_ms");
    web_json_epoch_ms(&w, ns.sntp_last_ms);
    gw_jw_obj_close(&w);
    gw_jw_obj_close(&w);
    return web_send_jw(c, 200, &w);
}

/* ---------------------------------------------------------------- firmware */

esp_err_t h_firmware_info(web_ctx_t *c) {
    sys_fw_info_t fi;
    esp_err_t e = sys_fw_info(&fi);
    if (e != ESP_OK) {
        return web_send_esp_err(c, e);
    }
    char buf[256];
    gw_jw_t w;
    gw_jw_init_fixed(&w, buf, sizeof(buf));
    gw_jw_obj_open(&w);
    gw_jw_kobj(&w, "running");
    gw_jw_kstr(&w, "slot", fi.running_slot);
    gw_jw_kstr(&w, "version", fi.running_version);
    gw_jw_kstr(&w, "state", fi.running_state);
    gw_jw_obj_close(&w);
    gw_jw_kobj(&w, "other");
    gw_jw_kstr(&w, "slot", fi.other_slot);
    if (fi.other_version[0]) {
        gw_jw_kstr(&w, "version", fi.other_version);
    } else {
        gw_jw_knull(&w, "version");
    }
    gw_jw_kbool(&w, "valid", fi.other_valid);
    gw_jw_obj_close(&w);
    gw_jw_obj_close(&w);
    return web_send_jw(c, 200, &w);
}

esp_err_t h_firmware_rollback(web_ctx_t *c) {
    esp_err_t e = sys_rollback(web_user(c));
    if (e == ESP_ERR_NOT_FOUND) {
        return web_send_error(c, 404, WEB_E_NOT_FOUND, "no valid image in the other slot", NULL);
    }
    if (e == ESP_ERR_INVALID_STATE) {
        return web_send_error(c, 409, WEB_E_CONFLICT, "a reboot is already scheduled", NULL);
    }
    if (e != ESP_OK) {
        return web_send_esp_err(c, e);
    }
    ESP_LOGW(TAG, "rollback requested by %s", web_user(c)); /* sys_rollback() audits */
    return send_reboot_in(c, SYS_OTA_REBOOT_DELAY_MS);
}

/* ---------------------------------------------------------------- reboot / factory reset */

esp_err_t h_system_reboot(web_ctx_t *c) {
    esp_err_t e = sys_reboot(GW_REBOOT_USER, REBOOT_DELAY_MS, web_user(c));
    if (e == ESP_ERR_INVALID_STATE) {
        return web_send_error(c, 409, WEB_E_CONFLICT, "a reboot is already scheduled", NULL);
    }
    if (e != ESP_OK) {
        return web_send_esp_err(c, e);
    }
    ESP_LOGW(TAG, "reboot requested by %s", web_user(c)); /* sys_reboot() audits AUD_REBOOT */
    return send_reboot_in(c, REBOOT_DELAY_MS);
}

esp_err_t h_factory_reset(web_ctx_t *c) {
    cJSON *root = web_body_object(c);
    if (!root) {
        return ESP_OK;
    }
    static const char *const allowed[] = {"password", "confirm", "keep_network", NULL};
    const char *pass = NULL, *confirm = NULL;
    bool keep = false, has_keep = false;
    esp_err_t ret = ESP_OK;
    if (web_json_only(c, root, allowed, NULL) && web_json_str(c, root, "password", 256, &pass, NULL) &&
        web_json_str(c, root, "confirm", 16, &confirm, NULL) &&
        web_json_bool(c, root, "keep_network", &keep, &has_keep)) {
        if (strcmp(confirm, "RESET") != 0) {
            ret = web_send_validation(c, "confirm", "format", "type RESET to confirm");
        } else {
            uint32_t retry = 0;
            auth_status_t st = auth_verify_session_password(c->sess.sid, pass, c->client_ip, &retry);
            if (st == AUTH_E_LOCKED) {
                ret = web_send_rate_limited(c, retry, "too many failed attempts");
            } else if (st == AUTH_E_WRONG_PASSWORD) {
                ret = web_send_error(c, 422, WEB_E_WRONG_PASSWORD, "password is wrong", "password");
            } else if (st != AUTH_OK) {
                ret = web_send_error(c, auth_http_status(st), auth_status_code(st), NULL, NULL);
            } else {
                esp_err_t e = sys_factory_reset(keep, web_user(c));
                if (e == ESP_OK) {
                    ESP_LOGW(TAG, "factory reset (keep_network=%d) by %s", keep, web_user(c));
                    ret = send_reboot_in(c, REBOOT_DELAY_MS);
                } else if (e == ESP_ERR_INVALID_STATE) {
                    ret = web_send_error(c, 409, WEB_E_CONFLICT, "a reboot is already scheduled", NULL);
                } else {
                    ret = web_send_esp_err(c, e);
                }
            }
        }
    }
    cJSON *p = cJSON_GetObjectItemCaseSensitive(root, "password");
    if (cJSON_IsString(p) && p->valuestring) {
        memset(p->valuestring, 0, strlen(p->valuestring));
    }
    cJSON_Delete(root);
    return ret;
}

/* ---------------------------------------------------------------- logs / core dump */

esp_err_t h_system_logs(web_ctx_t *c) {
    char kind_s[8] = "system";
    int64_t before = 0, limit = 50;
    web_q_t qk = web_query_str(c, "kind", kind_s, sizeof(kind_s));
    web_q_t qb = web_query_i64(c, "before", &before);
    web_q_t ql = web_query_i64(c, "limit", &limit);
    if (qk == WEB_Q_ABSENT) {
        strcpy(kind_s, "system");
    }
    const bool audit = strcmp(kind_s, "audit") == 0;
    if (qk == WEB_Q_INVALID || (!audit && strcmp(kind_s, "system") != 0) || qb == WEB_Q_INVALID ||
        ql == WEB_Q_INVALID || before < 0 || before > UINT32_MAX || limit < 1 || limit > EVLOG_QUERY_MAX) {
        return web_send_error(c, 400, WEB_E_BAD_REQUEST, "kind=audit|system, before>=0, limit 1..200", NULL);
    }
    evlog_rec_t *recs = malloc(sizeof(*recs) * EVLOG_QUERY_MAX);
    if (!recs) {
        return web_send_error(c, 503, WEB_E_UNAVAILABLE, NULL, NULL);
    }
    const evlog_filter_t any = EVLOG_FILTER_ANY;
    uint32_t next = 0;
    size_t n =
        evlog_query(audit ? EVLOG_AUDIT : EVLOG_EVENTS, (uint32_t)before, (size_t)limit, &any, recs, &next);
    gw_jw_t w;
    if (web_stream_begin(c, 200, "application/json", NULL, &w) != ESP_OK) {
        free(recs);
        return ESP_OK;
    }
    char user[13];
    char tname[16];
    gw_jw_obj_open(&w);
    gw_jw_kstr(&w, "kind", audit ? "audit" : "system");
    gw_jw_karr(&w, "items");
    for (size_t i = 0; i < n; i++) {
        const evlog_rec_t *r = &recs[i];
        memcpy(user, r->user, sizeof(r->user));
        user[12] = '\0';
        const char *tn = evlog_type_name(r->type);
        if (!tn || !tn[0]) {
            snprintf(tname, sizeof(tname), "type_%u", (unsigned)r->type);
            tn = tname;
        }
        gw_jw_obj_open(&w);
        gw_jw_kuint(&w, "seq", r->seq);
        gw_jw_key(&w, "ts");
        web_json_epoch_ms(&w, (int64_t)r->ts * 1000);
        gw_jw_kstr(&w, "type", tn);
        if (r->dev < GW_MAX_DEVICES) {
            gw_jw_kuint(&w, "dev", r->dev);
        } else {
            gw_jw_knull(&w, "dev");
        }
        gw_jw_kuint(&w, "code", r->code);
        gw_jw_kuint(&w, "sev", r->sev > 3 ? 3 : r->sev);
        gw_jw_kint(&w, "value", r->value);
        if (user[0]) {
            gw_jw_kstr(&w, "user", user);
        } else {
            gw_jw_knull(&w, "user");
        }
        gw_jw_kuint(&w, "extra", r->extra);
        gw_jw_obj_close(&w);
    }
    gw_jw_arr_close(&w);
    if (next) {
        gw_jw_kuint(&w, "next", next);
    } else {
        gw_jw_knull(&w, "next");
    }
    gw_jw_obj_close(&w);
    free(recs);
    return web_stream_end(c, &w);
}

esp_err_t h_coredump(web_ctx_t *c) {
    sys_coredump_summary_t *s = malloc(sizeof(*s));
    if (!s) {
        return web_send_error(c, 503, WEB_E_UNAVAILABLE, NULL, NULL);
    }
    esp_err_t e = sys_coredump_summary(s);
    if (e != ESP_OK) {
        free(s);
        return e == ESP_ERR_NOT_FOUND ? web_send_error(c, 404, WEB_E_NOT_FOUND, "no core dump stored", NULL)
                                      : web_send_esp_err(c, e);
    }
    char buf[512];
    gw_jw_t w;
    gw_jw_init_fixed(&w, buf, sizeof(buf));
    gw_jw_obj_open(&w);
    gw_jw_kstr(&w, "task", s->task);
    gw_jw_kuint(&w, "pc", s->pc);
    gw_jw_kuint(&w, "cause", s->cause);
    gw_jw_kuint(&w, "vaddr", s->vaddr);
    gw_jw_karr(&w, "backtrace");
    for (size_t i = 0; i < s->bt_depth && i < SYS_COREDUMP_BT_MAX; i++) {
        gw_jw_uint(&w, s->bt[i]);
    }
    gw_jw_arr_close(&w);
    gw_jw_kbool(&w, "backtrace_corrupted", s->bt_corrupted);
    gw_jw_kstr(&w, "app_sha256", s->app_sha256);
    gw_jw_obj_close(&w);
    free(s);
    return web_send_jw(c, 200, &w);
}

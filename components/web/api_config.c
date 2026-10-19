/* Configuration endpoints (docs/API.md §4.8, §4.11): /config/<section> (merge semantics),
 * /config/rules, provisional network change + confirm, SNMP with write-only secrets and key
 * localization, /time, /snmp/mib, /snmp/test-trap, config export/import. */
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_app_desc.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "gw_core/gw_crypto.h"
#include "gw_core/gw_events.h"
#include "gw_core/gw_time.h"
#include "net/ip_filter.h"
#include "net/net.h"
#include "snmp_gw/snmp_gw.h"
#include "store/config.h"
#include "store/config_json.h"
#include "store/eventlog.h"
#include "store/secrets.h"
#include "web_priv.h"

static const char *TAG = "api_cfg";

#define SECTION_JSON_MAX (8u * 1024u)
#define EXPORT_JSON_MAX (16u * 1024u)
#define SNMP_LOCK_WAIT_MS 3000

/* The SNMP secrets (communities, v3 keys, trap communities index-aligned with the trap list) and the
 * SNMP config section are changed together by PUT /config/snmp (control lane) and config import
 * (httpd task). This lock serializes those two paths so the revision check, the secrets change and
 * the config commit (with rollback of the secrets if the commit fails) form one unit. Leaf lock: only
 * store calls are made while it is held. */
static SemaphoreHandle_t s_snmp_lock;
static StaticSemaphore_t s_snmp_lock_buf;

esp_err_t web_api_config_init(void) {
    if (!s_snmp_lock) {
        s_snmp_lock = xSemaphoreCreateMutexStatic(&s_snmp_lock_buf);
    }
    return s_snmp_lock ? ESP_OK : ESP_ERR_NO_MEM;
}

static bool snmp_lock(void) {
    return s_snmp_lock && xSemaphoreTake(s_snmp_lock, pdMS_TO_TICKS(SNMP_LOCK_WAIT_MS)) == pdTRUE;
}

static void snmp_unlock(void) {
    xSemaphoreGive(s_snmp_lock);
}

/* SNMP-related secrets as they were before a change (restored if the config commit fails). */
typedef struct {
    char snmp_ro[GW_COMMUNITY_SZ];
    char snmp_rw[GW_COMMUNITY_SZ];
    sec_v3_keys_t v3[GW_MAX_SNMP_V3_USERS];
    char trap_comm[GW_MAX_TRAP_TARGETS][GW_COMMUNITY_SZ];
} snmp_sec_saved_t;

static void snmp_sec_save(const gw_secrets_t *s, snmp_sec_saved_t *o) {
    memcpy(o->snmp_ro, s->snmp_ro, sizeof(o->snmp_ro));
    memcpy(o->snmp_rw, s->snmp_rw, sizeof(o->snmp_rw));
    memcpy(o->v3, s->v3, sizeof(o->v3));
    memcpy(o->trap_comm, s->trap_comm, sizeof(o->trap_comm));
}

static esp_err_t snmp_sec_restore_fn(gw_secrets_t *s, void *arg) {
    const snmp_sec_saved_t *o = arg;
    memcpy(s->snmp_ro, o->snmp_ro, sizeof(s->snmp_ro));
    memcpy(s->snmp_rw, o->snmp_rw, sizeof(s->snmp_rw));
    memcpy(s->v3, o->v3, sizeof(s->v3));
    memcpy(s->trap_comm, o->trap_comm, sizeof(s->trap_comm));
    return ESP_OK;
}

/* Undo a secrets change after its config commit failed (caller holds the SNMP lock). */
static void snmp_sec_rollback(snmp_sec_saved_t *prev, const char *by) {
    esp_err_t e = secrets_modify(snmp_sec_restore_fn, prev, by);
    if (e != ESP_OK) {
        ESP_LOGE(TAG, "SNMP secrets rollback failed: %s", esp_err_to_name(e));
    }
}

/* PUT /config/security and config import: true (422 sent) if allowlist `sec` would exclude the
 * requesting client (the recovery AP is always exempt). */
static bool ip_allow_locks_out(web_ctx_t *c, const cfg_security_t *sec, const char *field) {
    uint32_t nets[GW_MAX_IP_ALLOW], masks[GW_MAX_IP_ALLOW];
    size_t n = sec->n_ip_allow <= GW_MAX_IP_ALLOW ? sec->n_ip_allow : GW_MAX_IP_ALLOW;
    for (size_t i = 0; i < n; i++) {
        nets[i] = sec->ip_allow[i].net;
        masks[i] = sec->ip_allow[i].mask;
    }
    ip_filter_t f;
    ip_filter_set(&f, nets, masks, n);
    if (!ip_filter_would_lock_out(&f, c->client_ip, c->via_ap)) {
        return false;
    }
    (void)web_send_validation(c, field, "lockout", "the list would exclude this client");
    return true;
}

/* ---------------------------------------------------------------- helpers */

/* Section named by the route pattern's last segment ("/api/v1/config/general" -> GENERAL). */
static bool route_section(const web_ctx_t *c, cfg_section_t *s) {
    const char *slash = strrchr(c->route->pattern, '/');
    return slash && cfg_section_from_name(slash + 1, s);
}

static gw_config_t *config_copy(void) {
    gw_config_t *cfg = malloc(sizeof(*cfg));
    if (cfg) {
        cfg_get(cfg);
    }
    return cfg;
}

static esp_err_t json_err(web_ctx_t *c, int rc, const cfg_verr_t *err) {
    switch (rc) {
    case CFG_JSON_E_PARSE:
        return web_send_error(c, 400, WEB_E_INVALID_JSON, "body is not valid JSON", NULL);
    case CFG_JSON_E_SCHEMA:
        return web_send_cfg_verr(c, err->field, "unsupported_schema");
    case CFG_JSON_E_INVALID:
        return web_send_cfg_verr(c, err->field, err->code);
    default:
        return web_send_error(c, 500, WEB_E_INTERNAL, NULL, NULL);
    }
}

static esp_err_t commit_err(web_ctx_t *c, esp_err_t e, const cfg_verr_t *err) {
    if (e == ESP_ERR_INVALID_ARG) {
        return web_send_cfg_verr(c, err->field, err->code);
    }
    if (e == ESP_ERR_INVALID_STATE) {
        return web_send_error(c, 409, WEB_E_CONFLICT, "configuration is frozen (factory reset pending)",
                              NULL);
    }
    return web_send_esp_err(c, e);
}

/* Strip "<prefix>." from a field path (store reports "snmp.ro"; PUT /config/snmp names "ro"). */
static const char *strip_prefix(const char *field, const char *prefix) {
    size_t n = strlen(prefix);
    if (field && strncmp(field, prefix, n) == 0 && field[n] == '.') {
        return field + n + 1;
    }
    return field;
}

/* Send section s of the CURRENT configuration (200). */
static esp_err_t send_section(web_ctx_t *c, cfg_section_t s) {
    gw_config_t *cfg = config_copy();
    if (!cfg) {
        return web_send_error(c, 503, WEB_E_UNAVAILABLE, NULL, NULL);
    }
    cfg_secret_flags_t flags;
    secrets_flags(&flags);
    gw_jw_t w;
    if (web_jw_dynamic(&w, SECTION_JSON_MAX) != GW_JW_OK) {
        free(cfg);
        return web_send_error(c, 503, WEB_E_UNAVAILABLE, NULL, NULL);
    }
    int rc = cfg_section_to_json(s, cfg, &flags, &w);
    free(cfg);
    if (rc != CFG_JSON_OK) {
        gw_jw_free(&w);
        ESP_LOGE(TAG, "section %d to json: %d", (int)s, rc);
        return web_send_error(c, 500, WEB_E_INTERNAL, NULL, NULL);
    }
    return web_send_jw_free(c, 200, &w);
}

/* ---------------------------------------------------------------- generic sections */

esp_err_t h_config_section_get(web_ctx_t *c) {
    cfg_section_t s;
    if (!route_section(c, &s)) {
        return web_send_error(c, 404, WEB_E_NOT_FOUND, NULL, NULL);
    }
    return send_section(c, s);
}

/* Parse + merge a section body onto the current config. On success *out holds the new section. */
static bool parse_section(web_ctx_t *c, cfg_section_t s, gw_config_t *cur, void *out,
                          cfg_secret_input_t *sec) {
    cfg_verr_t err;
    memset(&err, 0, sizeof(err));
    if (!c->body || !c->body_len) {
        web_send_error(c, 400, WEB_E_INVALID_JSON, "body required", NULL);
        return false;
    }
    int rc = cfg_section_from_json(s, c->body, c->body_len, cur, out, sec, &err);
    if (rc != CFG_JSON_OK) {
        json_err(c, rc, &err);
        return false;
    }
    return true;
}

static esp_err_t put_section(web_ctx_t *c, cfg_section_t s) {
    gw_config_t *cur = config_copy();
    void *sec = cur ? calloc(1, cfg_section_size(s)) : NULL;
    if (!cur || !sec) {
        free(cur);
        return web_send_error(c, 503, WEB_E_UNAVAILABLE, NULL, NULL);
    }
    esp_err_t ret = ESP_OK;
    if (parse_section(c, s, cur, sec, NULL)) {
        cfg_verr_t err;
        memset(&err, 0, sizeof(err));
        esp_err_t e = cfg_commit(s, sec, cfg_section_size(s), web_user(c), &err);
        ret = e == ESP_OK ? send_section(c, s) : commit_err(c, e, &err);
    }
    free(sec);
    free(cur);
    return ret;
}

esp_err_t h_config_section_put(web_ctx_t *c) {
    cfg_section_t s;
    if (!route_section(c, &s)) {
        return web_send_error(c, 404, WEB_E_NOT_FOUND, NULL, NULL);
    }
    return put_section(c, s);
}

esp_err_t h_config_security_put(web_ctx_t *c) {
    gw_config_t *cur = config_copy();
    cfg_security_t *sec = cur ? calloc(1, sizeof(*sec)) : NULL;
    if (!cur || !sec) {
        free(cur);
        return web_send_error(c, 503, WEB_E_UNAVAILABLE, NULL, NULL);
    }
    esp_err_t ret = ESP_OK;
    if (parse_section(c, CFG_SEC_SECURITY, cur, sec, NULL)) {
        if (!ip_allow_locks_out(c, sec, "ip_allow")) {
            cfg_verr_t err;
            memset(&err, 0, sizeof(err));
            esp_err_t e = cfg_commit(CFG_SEC_SECURITY, sec, sizeof(*sec), web_user(c), &err);
            ret = e == ESP_OK ? send_section(c, CFG_SEC_SECURITY) : commit_err(c, e, &err);
        }
    }
    free(sec);
    free(cur);
    return ret;
}

/* ---------------------------------------------------------------- rules */

esp_err_t h_config_rules_get(web_ctx_t *c) {
    cfg_alarms_t *a = malloc(sizeof(*a));
    if (!a || cfg_get_section(CFG_SEC_ALARMS, a, sizeof(*a)) != ESP_OK) {
        free(a);
        return web_send_error(c, 503, WEB_E_UNAVAILABLE, NULL, NULL);
    }
    gw_jw_t w;
    if (web_jw_dynamic(&w, SECTION_JSON_MAX) != GW_JW_OK) {
        free(a);
        return web_send_error(c, 503, WEB_E_UNAVAILABLE, NULL, NULL);
    }
    int rc = cfg_rules_to_json(a, &w);
    free(a);
    if (rc != CFG_JSON_OK) {
        gw_jw_free(&w);
        return web_send_error(c, 500, WEB_E_INTERNAL, NULL, NULL);
    }
    return web_send_jw_free(c, 200, &w);
}

esp_err_t h_config_rules_put(web_ctx_t *c) {
    if (!c->body || !c->body_len) {
        return web_send_error(c, 400, WEB_E_INVALID_JSON, "body required", NULL);
    }
    cfg_alarms_t *a = malloc(sizeof(*a));
    if (!a || cfg_get_section(CFG_SEC_ALARMS, a, sizeof(*a)) != ESP_OK) {
        free(a);
        return web_send_error(c, 503, WEB_E_UNAVAILABLE, NULL, NULL);
    }
    cfg_verr_t err;
    memset(&err, 0, sizeof(err));
    esp_err_t ret;
    int rc = cfg_rules_from_json(c->body, c->body_len, a, &err);
    if (rc != CFG_JSON_OK) {
        ret = json_err(c, rc, &err);
    } else {
        esp_err_t e = cfg_commit(CFG_SEC_ALARMS, a, sizeof(*a), web_user(c), &err);
        ret = e == ESP_OK ? h_config_rules_get(c) : commit_err(c, e, &err);
    }
    free(a);
    return ret;
}

/* ---------------------------------------------------------------- network */

/* GET body: the section from store plus the live "provisional" member from net. */
esp_err_t h_config_network_get(web_ctx_t *c) {
    gw_config_t *cfg = config_copy();
    if (!cfg) {
        return web_send_error(c, 503, WEB_E_UNAVAILABLE, NULL, NULL);
    }
    cfg_secret_flags_t flags;
    secrets_flags(&flags);
    net_status_t ns;
    net_get_status(&ns);
    char prov[64] = "";
    if (ns.prov == NET_PROV_APPLY_PENDING || ns.prov == NET_PROV_AWAIT_CONFIRM) {
        snprintf(prov, sizeof(prov), "{\"state\":\"%s\",\"left_s\":%u}",
                 ns.prov == NET_PROV_APPLY_PENDING ? "apply_pending" : "await_confirm",
                 (unsigned)ns.prov_left_s);
    }
    gw_jw_t w;
    if (web_jw_dynamic(&w, SECTION_JSON_MAX) != GW_JW_OK) {
        free(cfg);
        return web_send_error(c, 503, WEB_E_UNAVAILABLE, NULL, NULL);
    }
    int rc = cfg_network_to_json(cfg, &flags, prov, &w);
    free(cfg);
    if (rc != CFG_JSON_OK) {
        gw_jw_free(&w);
        return web_send_error(c, 500, WEB_E_INTERNAL, NULL, NULL);
    }
    return web_send_jw_free(c, 200, &w);
}

esp_err_t h_config_network_put(web_ctx_t *c) {
    gw_config_t *cur = config_copy();
    cfg_network_t *net = cur ? calloc(1, sizeof(*net)) : NULL;
    cfg_secret_input_t *sec = net ? calloc(1, sizeof(*sec)) : NULL;
    if (!cur || !net || !sec) {
        free(cur);
        free(net);
        return web_send_error(c, 503, WEB_E_UNAVAILABLE, NULL, NULL);
    }
    esp_err_t ret = ESP_OK;
    if (parse_section(c, CFG_SEC_NETWORK, cur, net, sec)) {
        cfg_verr_t err;
        memset(&err, 0, sizeof(err));
        if (!cfg_validate_with(cur, CFG_SEC_NETWORK, net, &err)) {
            ret = web_send_cfg_verr(c, err.field, err.code);
        } else {
            esp_err_t e = net_apply_provisional(net, sec->has_ap_psk ? sec->ap_psk : NULL, NET_APPLY_DELAY_S,
                                                NET_CONFIRM_S, web_user(c));
            if (e == ESP_OK) {
                char body[64];
                int n = snprintf(body, sizeof(body), "{\"apply_in_s\":%u,\"confirm_within_s\":%u}",
                                 (unsigned)NET_APPLY_DELAY_S, (unsigned)NET_CONFIRM_S);
                ret = web_send_json(c, 202, body, (size_t)n);
            } else if (e == ESP_ERR_INVALID_STATE) {
                ret = web_send_error(c, 423, WEB_E_LOCKED, "a network change is already pending", NULL);
            } else if (e == ESP_ERR_INVALID_ARG) {
                ret = web_send_validation(c, sec->has_ap_psk ? "ap.psk" : NULL, "format", NULL);
            } else {
                ret = web_send_esp_err(c, e);
            }
        }
    }
    gw_secure_zero(sec, sizeof(*sec));
    free(sec);
    free(net);
    free(cur);
    return ret;
}

esp_err_t h_config_network_confirm(web_ctx_t *c) {
    /* Only an APPLIED change can be confirmed (the client proved it reaches the new address);
     * same answer as the mock while the change is still scheduled (DECISIONS.md C). */
    net_status_t ns;
    net_get_status(&ns);
    if (ns.prov != NET_PROV_AWAIT_CONFIRM) {
        return web_send_error(c, 409, WEB_E_CONFLICT, "no network change awaiting confirmation", NULL);
    }
    esp_err_t e = net_confirm(web_user(c));
    if (e == ESP_OK) {
        return web_send_status(c, 204);
    }
    if (e == ESP_ERR_INVALID_STATE) {
        return web_send_error(c, 409, WEB_E_CONFLICT, "no network change is pending", NULL);
    }
    return web_send_esp_err(c, e);
}

/* ---------------------------------------------------------------- SNMP */

typedef struct {
    const cfg_secret_input_t *in;
    uint8_t n_traps;
    snmp_sec_saved_t prev; /* filled by snmp_sec_fn from the current secrets */
    bool set_auth[GW_MAX_SNMP_V3_USERS];
    bool set_priv[GW_MAX_SNMP_V3_USERS];
    uint8_t auth[GW_MAX_SNMP_V3_USERS][SEC_V3_KEY_LEN];
    uint8_t priv[GW_MAX_SNMP_V3_USERS][SEC_V3_KEY_LEN];
} snmp_sec_op_t;

static esp_err_t snmp_sec_fn(gw_secrets_t *s, void *arg) {
    snmp_sec_op_t *op = arg;
    snmp_sec_save(s, &op->prev);
    if (op->in->has_snmp_ro) {
        gw_strlcpy(s->snmp_ro, op->in->snmp_ro, sizeof(s->snmp_ro));
    }
    if (op->in->has_snmp_rw) {
        gw_strlcpy(s->snmp_rw, op->in->snmp_rw, sizeof(s->snmp_rw));
    }
    for (size_t i = 0; i < GW_MAX_SNMP_V3_USERS; i++) {
        if (!op->set_auth[i] && !op->set_priv[i]) {
            continue;
        }
        if (!s->v3[i].set && !(op->set_auth[i] && op->set_priv[i])) {
            return ESP_ERR_INVALID_STATE; /* re-checked under the lock */
        }
        if (op->set_auth[i]) {
            memcpy(s->v3[i].auth_key, op->auth[i], SEC_V3_KEY_LEN);
        }
        if (op->set_priv[i]) {
            memcpy(s->v3[i].priv_key, op->priv[i], SEC_V3_KEY_LEN);
        }
        s->v3[i].set = true;
    }
    if (op->in->has_traps) {
        sec_trap_remap(s, op->in, op->n_traps);
    } else {
        for (size_t i = 0; i < GW_MAX_TRAP_TARGETS && i < op->n_traps; i++) {
            if (op->in->trap[i].has) {
                gw_strlcpy(s->trap_comm[i], op->in->trap[i].community, sizeof(s->trap_comm[i]));
            }
        }
    }
    return ESP_OK;
}

static bool pass_len_ok(web_ctx_t *c, size_t slot, const char *which, const char *pass) {
    size_t n = strlen(pass);
    if (n < GW_SNMP_PASS_MIN || n > GW_SNMP_PASS_MAX) {
        char field[40];
        snprintf(field, sizeof(field), "v3.users[%u].%s", (unsigned)slot, which);
        web_send_validation(c, field, "length", "8..64 characters");
        return false;
    }
    return true;
}

esp_err_t h_config_snmp_put(web_ctx_t *c) {
    gw_config_t *cur = config_copy();
    cfg_snmp_t *snmp = cur ? calloc(1, sizeof(*snmp)) : NULL;
    cfg_snmp_t *snmp_now = snmp ? malloc(sizeof(*snmp_now)) : NULL;
    cfg_secret_input_t *in = snmp_now ? calloc(1, sizeof(*in)) : NULL;
    snmp_sec_op_t *op = in ? calloc(1, sizeof(*op)) : NULL;
    if (!op) {
        free(in);
        free(snmp_now);
        free(snmp);
        free(cur);
        return web_send_error(c, 503, WEB_E_UNAVAILABLE, NULL, NULL);
    }
    esp_err_t ret = ESP_OK;
    cfg_verr_t err;
    memset(&err, 0, sizeof(err));
    if (!parse_section(c, CFG_SEC_SNMP, cur, snmp, in)) {
        goto out;
    }
    if (!cfg_validate_with(cur, CFG_SEC_SNMP, snmp, &err)) {
        ret = web_send_cfg_verr(c, strip_prefix(err.field, "snmp"), err.code);
        goto out;
    }
    cfg_secret_flags_t after;
    secrets_flags(&after); /* pre-check only; repeated under the SNMP lock below */
    for (size_t i = 0; i < GW_MAX_SNMP_V3_USERS; i++) {
        const bool ha = in->v3[i].has_auth, hp = in->v3[i].has_priv;
        if (!ha && !hp) {
            continue;
        }
        if ((ha && !pass_len_ok(c, i, "auth_pass", in->v3[i].auth_pass)) ||
            (hp && !pass_len_ok(c, i, "priv_pass", in->v3[i].priv_pass))) {
            goto out;
        }
        if (!(ha && hp) && !after.v3_keys_set[i]) {
            char field[40];
            snprintf(field, sizeof(field), "v3.users[%u].%s", (unsigned)i, ha ? "priv_pass" : "auth_pass");
            ret = web_send_validation(c, field, "required", "both passphrases are needed for a new user");
            goto out;
        }
        if ((ha && snmp_gw_localize_key(in->v3[i].auth_pass, op->auth[i]) != ESP_OK) ||
            (hp && snmp_gw_localize_key(in->v3[i].priv_pass, op->priv[i]) != ESP_OK)) {
            ret = web_send_error(c, 500, WEB_E_INTERNAL, "key localization failed", NULL);
            goto out;
        }
        op->set_auth[i] = ha;
        op->set_priv[i] = hp;
    }
    op->in = in;
    op->n_traps = snmp->n_traps;
    if (!snmp_lock()) {
        ret = web_send_error(c, 503, WEB_E_BUSY, NULL, NULL);
        goto out;
    }
    /* The trap-community remap was computed against cur->snmp: refuse if it changed meanwhile. */
    if (cfg_get_section(CFG_SEC_SNMP, snmp_now, sizeof(*snmp_now)) != ESP_OK ||
        memcmp(snmp_now, &cur->snmp, sizeof(*snmp_now)) != 0) {
        snmp_unlock();
        ret = web_send_error(c, 409, WEB_E_CONFLICT, "SNMP configuration changed meanwhile; reload", NULL);
        goto out;
    }
    /* Secrets as they will be after this change -> v1/v2c need a RO community. */
    secrets_flags(&after);
    if (in->has_snmp_ro) {
        after.snmp_ro_set = in->snmp_ro[0] != '\0';
    }
    if (in->has_snmp_rw) {
        after.snmp_rw_set = in->snmp_rw[0] != '\0';
    }
    if (!cfg_snmp_check_secrets(snmp, &after, &err)) {
        snmp_unlock();
        ret = web_send_cfg_verr(c, strip_prefix(err.field, "snmp"), err.code);
        goto out;
    }
    esp_err_t e = secrets_modify(snmp_sec_fn, op, web_user(c));
    if (e != ESP_OK) {
        snmp_unlock();
        ESP_LOGE(TAG, "snmp secrets: %s", esp_err_to_name(e));
        ret = e == ESP_ERR_INVALID_STATE ? web_send_error(c, 409, WEB_E_CONFLICT, NULL, NULL)
                                         : web_send_error(c, 503, WEB_E_UNAVAILABLE, NULL, NULL);
        goto out;
    }
    e = cfg_commit(CFG_SEC_SNMP, snmp, sizeof(*snmp), web_user(c), &err);
    if (e != ESP_OK) {
        snmp_sec_rollback(&op->prev, web_user(c));
    }
    snmp_unlock();
    ret = e == ESP_OK ? send_section(c, CFG_SEC_SNMP) : commit_err(c, e, &err);
out:
    gw_secure_zero(op, sizeof(*op));
    gw_secure_zero(in, sizeof(*in));
    free(op);
    free(in);
    free(snmp_now);
    free(snmp);
    free(cur);
    return ret;
}

esp_err_t h_snmp_mib(web_ctx_t *c) {
    size_t len = 0;
    const uint8_t *gz = snmp_gw_mib_gz(&len);
    if (!gz || !len) {
        return web_send_error(c, 404, WEB_E_NOT_FOUND, NULL, NULL);
    }
    web_set_header(c, "Content-Encoding", "gzip");
    web_set_header(c, "Content-Disposition", "attachment; filename=\"MESTIO-GW-MIB.txt\"");
    return web_send_body(c, 200, "text/plain; charset=utf-8", (const char *)gz, len);
}

esp_err_t h_snmp_test_trap(web_ctx_t *c) {
    cfg_snmp_t *snmp = malloc(sizeof(*snmp));
    cfg_security_t sec;
    if (!snmp || cfg_get_section(CFG_SEC_SNMP, snmp, sizeof(*snmp)) != ESP_OK ||
        cfg_get_section(CFG_SEC_SECURITY, &sec, sizeof(sec)) != ESP_OK) {
        free(snmp);
        return web_send_error(c, 503, WEB_E_UNAVAILABLE, NULL, NULL);
    }
    bool any = false;
    for (size_t i = 0; i < snmp->n_traps && i < GW_MAX_TRAP_TARGETS; i++) {
        any = any || snmp->traps[i].enabled;
    }
    const bool on = snmp->enabled && sec.svc_snmp;
    free(snmp);
    if (!on || !any) {
        return web_send_error(c, 409, WEB_E_CONFLICT, on ? "no trap target is enabled" : "SNMP is disabled",
                              NULL);
    }
    snmp_gw_test_result_t res[GW_MAX_TRAP_TARGETS];
    size_t n = snmp_gw_test_trap(res, GW_MAX_TRAP_TARGETS, SNMP_GW_INFORM_TIMEOUT_MS);
    evlog_audit(AUD_SNMP_TEST, EVLOG_DEV_NONE, 0, (int16_t)n, web_user(c), 0);
    char buf[384];
    gw_jw_t w;
    gw_jw_init_fixed(&w, buf, sizeof(buf));
    gw_jw_obj_open(&w);
    gw_jw_karr(&w, "sent");
    for (size_t i = 0; i < n && i < GW_MAX_TRAP_TARGETS; i++) {
        gw_jw_obj_open(&w);
        gw_jw_kstr(&w, "host", res[i].host);
        gw_jw_kbool(&w, "ok", res[i].ok);
        gw_jw_obj_close(&w);
    }
    gw_jw_arr_close(&w);
    gw_jw_obj_close(&w);
    return web_send_jw(c, 200, &w);
}

/* ---------------------------------------------------------------- time */

esp_err_t h_time_set(web_ctx_t *c) {
    cJSON *root = web_body_object(c);
    if (!root) {
        return ESP_OK;
    }
    static const char *const allowed[] = {"epoch_ms", NULL};
    int64_t ms = 0;
    esp_err_t ret = ESP_OK;
    if (web_json_only(c, root, allowed, NULL) &&
        web_json_int(c, root, "epoch_ms", GW_TIME_VALID_MIN_S * 1000LL, 4102444800000LL, &ms, NULL)) {
        if (!gw_time_set_wall_ms(ms, GW_TIME_SRC_BROWSER, web_user(c))) {
            ret = web_send_validation(c, "epoch_ms", "range", "before 2024-01-01");
        } else {
            evlog_audit(AUD_TIME_SET, EVLOG_DEV_NONE, GW_TIME_SRC_BROWSER, 0, web_user(c), 0);
            ret = web_send_status(c, 204);
        }
    }
    cJSON_Delete(root);
    return ret;
}

/* ---------------------------------------------------------------- export / import */

esp_err_t h_config_export(web_ctx_t *c) {
    gw_config_t *cfg = config_copy();
    if (!cfg) {
        return web_send_error(c, 503, WEB_E_UNAVAILABLE, NULL, NULL);
    }
    gw_jw_t w;
    if (web_jw_dynamic(&w, EXPORT_JSON_MAX) != GW_JW_OK) {
        free(cfg);
        return web_send_error(c, 503, WEB_E_UNAVAILABLE, NULL, NULL);
    }
    const esp_app_desc_t *app = esp_app_get_description();
    int rc = cfg_to_json(cfg, app->version, &w);
    char fname[80];
    snprintf(fname, sizeof(fname), "mestio-gw-config-%s-%" PRIu32 ".json", cfg->network.hostname, cfg->rev);
    free(cfg);
    if (rc != CFG_JSON_OK || gw_jw_finish(&w) != GW_JW_OK) {
        gw_jw_free(&w);
        return web_send_error(c, 500, WEB_E_INTERNAL, NULL, NULL);
    }
    esp_err_t err = ESP_OK;
    if (web_stream_begin(c, 200, "application/json", fname, NULL) == ESP_OK) {
        err = web_stream_write(c, gw_jw_data(&w), gw_jw_length(&w));
        err = err == ESP_OK ? web_stream_end(c, NULL) : ESP_FAIL;
    }
    gw_jw_free(&w);
    return err;
}

typedef struct {
    cfg_secret_input_t in;
    uint8_t n_traps;
    snmp_sec_saved_t prev;
    cfg_snmp_t snmp_now; /* SNMP section current under the SNMP lock (remap source) */
} import_sec_t;

static esp_err_t import_sec_fn(gw_secrets_t *s, void *arg) {
    import_sec_t *op = arg;
    snmp_sec_save(s, &op->prev);
    sec_trap_remap(s, &op->in, op->n_traps);
    return ESP_OK;
}

esp_err_t h_config_import(web_ctx_t *c) {
    bool include_network = false;
    if (web_query_bool(c, "include_network", &include_network) == WEB_Q_INVALID) {
        return web_send_error(c, 400, WEB_E_BAD_REQUEST, "include_network must be 0/1", NULL);
    }
    if (!c->body || !c->body_len) {
        return web_send_error(c, 400, WEB_E_INVALID_JSON, "body required", NULL);
    }
    uint8_t mac[GW_MAC_LEN] = {0};
    esp_efuse_mac_get_default(mac);
    gw_config_t *cur = config_copy();
    gw_config_t *nw = cur ? malloc(sizeof(*nw)) : NULL;
    import_sec_t *sec = nw ? calloc(1, sizeof(*sec)) : NULL;
    if (!sec) {
        free(nw);
        free(cur);
        return web_send_error(c, 503, WEB_E_UNAVAILABLE, NULL, NULL);
    }
    esp_err_t ret = ESP_OK;
    cfg_verr_t err;
    memset(&err, 0, sizeof(err));
    int rc = cfg_from_json(c->body, c->body_len, mac, nw, &err);
    if (rc != CFG_JSON_OK) {
        ret = json_err(c, rc, &err);
        goto out;
    }
    cfg_network_t imported_net = nw->network;
    nw->network = cur->network; /* network is never committed directly (provisional or ignored) */
    if (include_network) {
        net_status_t ns;
        net_get_status(&ns);
        if (ns.prov == NET_PROV_APPLY_PENDING || ns.prov == NET_PROV_AWAIT_CONFIRM) {
            ret = web_send_error(c, 423, WEB_E_LOCKED, "a network change is already pending", NULL);
            goto out;
        }
        if (!cfg_validate_with(nw, CFG_SEC_NETWORK, &imported_net, &err)) {
            ret = web_send_cfg_verr(c, err.field, err.code);
            goto out;
        }
    }
    if (!cfg_validate(nw, &err)) {
        ret = web_send_cfg_verr(c, err.field, err.code);
        goto out;
    }
    /* Same lock-out guard as PUT /config/security: a bundle from another site must not cut off the
     * administrator restoring it (only the recovery AP would still reach the device). */
    if (ip_allow_locks_out(c, &nw->security, "security.ip_allow")) {
        goto out;
    }
    if (!snmp_lock()) {
        ret = web_send_error(c, 503, WEB_E_BUSY, NULL, NULL);
        goto out;
    }
    cfg_secret_flags_t flags;
    secrets_flags(&flags);
    if (!cfg_snmp_check_secrets(&nw->snmp, &flags, &err)) {
        snmp_unlock();
        ret = web_send_cfg_verr(c, err.field, err.code);
        goto out;
    }
    /* Trap communities follow (host, port): remap against the trap list current NOW (under the
     * lock), before the new list is committed. */
    if (cfg_get_section(CFG_SEC_SNMP, &sec->snmp_now, sizeof(sec->snmp_now)) != ESP_OK) {
        snmp_unlock();
        ret = web_send_error(c, 503, WEB_E_UNAVAILABLE, NULL, NULL);
        goto out;
    }
    sec->in.has_traps = true;
    cfg_trap_remap(&sec->snmp_now, &nw->snmp, sec->in.trap_from);
    sec->n_traps = nw->snmp.n_traps;
    esp_err_t e = secrets_modify(import_sec_fn, sec, web_user(c));
    if (e != ESP_OK) {
        snmp_unlock();
        ret = e == ESP_ERR_INVALID_STATE ? web_send_error(c, 409, WEB_E_CONFLICT, NULL, NULL)
                                         : web_send_error(c, 503, WEB_E_UNAVAILABLE, NULL, NULL);
        goto out;
    }
    e = cfg_commit_all(nw, web_user(c), &err);
    if (e != ESP_OK) {
        snmp_sec_rollback(&sec->prev, web_user(c));
        snmp_unlock();
        ret = commit_err(c, e, &err);
        goto out;
    }
    snmp_unlock();
    bool net_applied = false;
    if (include_network && memcmp(&imported_net, &cur->network, sizeof(imported_net)) != 0) {
        e = net_apply_provisional(&imported_net, NULL, NET_APPLY_DELAY_S, NET_CONFIRM_S, web_user(c));
        if (e != ESP_OK) {
            ESP_LOGW(TAG, "import: provisional network apply failed: %s", esp_err_to_name(e));
        }
        net_applied = e == ESP_OK;
    }
    const uint32_t rev = cfg_rev();
    evlog_audit(AUD_CONFIG_IMPORT, EVLOG_DEV_NONE, 0, include_network ? 1 : 0, web_user(c), rev);

    char buf[256];
    gw_jw_t w;
    gw_jw_init_fixed(&w, buf, sizeof(buf));
    gw_jw_obj_open(&w);
    gw_jw_kuint(&w, "rev", rev);
    gw_jw_karr(&w, "changed");
    for (int s = 0; s < CFG_SEC_COUNT; s++) {
        if (s == CFG_SEC_NETWORK) {
            continue;
        }
        const void *a = cfg_section_cptr(cur, (cfg_section_t)s);
        const void *b = cfg_section_cptr(nw, (cfg_section_t)s);
        if (a && b && memcmp(a, b, cfg_section_size((cfg_section_t)s)) != 0) {
            gw_jw_str(&w, cfg_section_name((cfg_section_t)s));
        }
    }
    gw_jw_arr_close(&w);
    gw_jw_key(&w, "network");
    if (net_applied) {
        gw_jw_obj_open(&w);
        gw_jw_kuint(&w, "apply_in_s", NET_APPLY_DELAY_S);
        gw_jw_kuint(&w, "confirm_within_s", NET_CONFIRM_S);
        gw_jw_obj_close(&w);
    } else {
        gw_jw_null(&w);
    }
    gw_jw_obj_close(&w);
    ret = web_send_jw(c, 200, &w);
out:
    gw_secure_zero(sec, sizeof(*sec));
    free(sec);
    free(nw);
    free(cur);
    return ret;
}

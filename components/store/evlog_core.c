/*
 * evlog_core.c - two-file 32-byte record rings, paging queries and type names (pure C, stdio).
 * Contracts: evlog_core.h (store-internal) and evlog_type_name() of store/eventlog.h.
 */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "evlog_core.h"

#define REC_SZ ((long)sizeof(evlog_rec_t))
#define READ_CHUNK 16

/* ------------------------------------------------------------------ type names */

const char *evlog_type_name(uint8_t type) {
    switch (type) {
    case EVT_ALARM_RAISE:
        return "alarm_raise";
    case EVT_ALARM_CLEAR:
        return "alarm_clear";
    case EVT_ALARM_ACK:
        return "alarm_ack";
    case EVT_COMM_LOST:
        return "comm_lost";
    case EVT_COMM_RESTORED:
        return "comm_restored";
    case EVT_BOOT:
        return "boot";
    case EVT_TIME_SET:
        return "time_set";
    case EVT_NET_LINK:
        return "net_link";
    case EVT_AP:
        return "ap";
    case EVT_OTA:
        return "ota";
    case EVT_REBOOT:
        return "reboot";
    case EVT_NET_PROVISIONAL:
        return "net_provisional";
    case EVT_HEALTH:
        return "health";
    case AUD_LOGIN_OK:
        return "login_ok";
    case AUD_LOGIN_FAIL:
        return "login_fail";
    case AUD_LOCKOUT:
        return "lockout";
    case AUD_LOGOUT:
        return "logout";
    case AUD_PASSWORD:
        return "password";
    case AUD_USER_ADD:
        return "user_add";
    case AUD_USER_MOD:
        return "user_mod";
    case AUD_USER_DEL:
        return "user_del";
    case AUD_CONFIG_CHANGE:
        return "config_change";
    case AUD_REG_WRITE:
        return "reg_write";
    case AUD_OTA_UPLOAD:
        return "ota_upload";
    case AUD_ROLLBACK:
        return "rollback";
    case AUD_REBOOT:
        return "reboot_req";
    case AUD_FACTORY_RESET:
        return "factory_reset";
    case AUD_CONFIG_IMPORT:
        return "config_import";
    case AUD_TIME_SET:
        return "time_sync";
    case AUD_ALARM_ACK:
        return "alarm_ack_req";
    case AUD_STATS_RESET:
        return "stats_reset";
    case AUD_SNMP_TEST:
        return "snmp_test";
    case AUD_HISTORY_DELETE:
        return "history_delete";
    case AUD_USER_TARGET:
        return "user_target";
    default:
        return "unknown";
    }
}

/* ------------------------------------------------------------------ files */

/* Re-read the size of file i, cut a torn tail and return the record count (0 if missing). */
static uint32_t sync_count(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0 || st.st_size <= 0)
        return 0;
    long torn = (long)(st.st_size % REC_SZ);
    if (torn) {
        if (truncate(path, (off_t)(st.st_size - torn)) != 0)
            return (uint32_t)(st.st_size / REC_SZ); /* still readable up to the last whole record */
    }
    long n = (long)(st.st_size / REC_SZ);
    return n > (long)EVLOG_RECS_PER_FILE ? EVLOG_RECS_PER_FILE : (uint32_t)n;
}

static bool read_rec(const char *path, uint32_t idx, evlog_rec_t *out) {
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    bool ok = fseek(f, (long)idx * REC_SZ, SEEK_SET) == 0 && fread(out, sizeof(*out), 1, f) == 1;
    fclose(f);
    return ok;
}

esp_err_t evlog_files_open(evlog_files_t *f, const char *dir, const char *name) {
    memset(f, 0, sizeof(*f));
    for (int i = 0; i < 2; i++) {
        int n = snprintf(f->path[i], sizeof(f->path[i]), "%s/%s.%d", dir, name, i);
        if (n <= 0 || n >= (int)sizeof(f->path[i]))
            return ESP_ERR_INVALID_ARG;
    }
    uint32_t last[2] = {0, 0};
    for (int i = 0; i < 2; i++) {
        f->count[i] = sync_count(f->path[i]);
        evlog_rec_t r;
        if (f->count[i] && read_rec(f->path[i], f->count[i] - 1, &r))
            last[i] = r.seq;
    }
    f->active = last[1] > last[0] ? 1 : 0;
    f->last_seq = last[f->active];
    return ESP_OK;
}

static esp_err_t append_chunk(evlog_files_t *f, const evlog_rec_t *recs, size_t n) {
    uint8_t a = f->active;
    FILE *fp = fopen(f->path[a], "ab");
    if (!fp)
        return ESP_FAIL;
    bool ok = fwrite(recs, sizeof(*recs), n, fp) == n;
    ok = ok && fflush(fp) == 0;
    ok = ok && fsync(fileno(fp)) == 0;
    if (fclose(fp) != 0)
        ok = false;
    if (!ok) {
        f->count[a] = sync_count(f->path[a]);
        return ESP_FAIL;
    }
    f->count[a] += (uint32_t)n;
    f->last_seq = recs[n - 1].seq;
    return ESP_OK;
}

static esp_err_t rotate(evlog_files_t *f) {
    uint8_t o = (uint8_t)(1 - f->active);
    FILE *fp = fopen(f->path[o], "wb"); /* truncate the older file */
    if (!fp)
        return ESP_FAIL;
    if (fclose(fp) != 0)
        return ESP_FAIL;
    f->count[o] = 0;
    f->active = o;
    return ESP_OK;
}

esp_err_t evlog_files_append(evlog_files_t *f, const evlog_rec_t *recs, size_t n) {
    while (n) {
        if (f->count[f->active] >= EVLOG_RECS_PER_FILE) {
            esp_err_t rc = rotate(f);
            if (rc != ESP_OK)
                return rc;
        }
        size_t room = EVLOG_RECS_PER_FILE - f->count[f->active];
        size_t k = n < room ? n : room;
        esp_err_t rc = append_chunk(f, recs, k);
        if (rc != ESP_OK)
            return rc;
        recs += k;
        n -= k;
    }
    return ESP_OK;
}

esp_err_t evlog_files_clear(evlog_files_t *f) {
    esp_err_t rc = ESP_OK;
    for (int i = 0; i < 2; i++) {
        if (remove(f->path[i]) != 0) {
            struct stat st;
            if (stat(f->path[i], &st) == 0)
                rc = ESP_FAIL;
        }
        f->count[i] = 0;
    }
    f->active = 0;
    return rc;
}

/* ------------------------------------------------------------------ query */

bool evlog_filter_match(const evlog_filter_t *f, const evlog_rec_t *r) {
    if (!f)
        return true;
    if (f->dev >= 0 && r->dev != (uint16_t)f->dev)
        return false;
    if (f->min_sev >= 0 && r->sev < (uint8_t)f->min_sev)
        return false;
    if (r->type < f->type_min || r->type > f->type_max)
        return false;
    return true;
}

typedef struct {
    const evlog_filter_t *flt;
    evlog_rec_t *out;
    size_t limit, count;
    uint32_t upper; /* only seq < upper */
    bool more;      /* a match beyond `limit` exists */
} qstate_t;

/* Returns false to stop scanning. */
static bool q_offer(qstate_t *q, const evlog_rec_t *r) {
    if (r->seq == 0 || r->seq >= q->upper || r->type == 0)
        return true;
    q->upper = r->seq; /* strictly descending: duplicates and stale records are skipped */
    if (!evlog_filter_match(q->flt, r))
        return true;
    if (q->count < q->limit) {
        q->out[q->count++] = *r;
        return true;
    }
    q->more = true;
    return false;
}

static bool scan_file_desc(const char *path, uint32_t count, qstate_t *q) {
    if (!count)
        return true;
    FILE *fp = fopen(path, "rb");
    if (!fp)
        return true;
    evlog_rec_t buf[READ_CHUNK];
    uint32_t pos = count;
    bool go = true;
    while (go && pos > 0) {
        uint32_t k = pos < READ_CHUNK ? pos : READ_CHUNK;
        pos -= k;
        if (fseek(fp, (long)pos * REC_SZ, SEEK_SET) != 0 || fread(buf, sizeof(buf[0]), k, fp) != k)
            break;
        for (uint32_t i = k; i-- > 0;) {
            if (!q_offer(q, &buf[i])) {
                go = false;
                break;
            }
        }
    }
    fclose(fp);
    return go;
}

size_t evlog_core_query(const evlog_files_t *f, const evlog_rec_t *ram, size_t n_ram, uint32_t before,
                        size_t limit, const evlog_filter_t *flt, evlog_rec_t *out, uint32_t *next) {
    if (next)
        *next = 0;
    if (limit > EVLOG_QUERY_MAX)
        limit = EVLOG_QUERY_MAX;
    if (!out || limit == 0)
        return 0;
    qstate_t q = {.flt = flt, .out = out, .limit = limit, .count = 0, .upper = before ? before : UINT32_MAX};
    bool go = true;
    for (size_t i = n_ram; go && i-- > 0;)
        go = q_offer(&q, &ram[i]);
    if (go && f) {
        /* Everything at or above the oldest RAM record is already covered by the RAM tail. */
        if (n_ram && ram[0].seq < q.upper)
            q.upper = ram[0].seq;
        uint8_t a = f->active;
        go = scan_file_desc(f->path[a], f->count[a], &q);
        if (go)
            go = scan_file_desc(f->path[1 - a], f->count[1 - a], &q);
    }
    if (q.more && q.count && next)
        *next = q.out[q.count - 1].seq;
    return q.count;
}

bool evlog_delete_match(const evlog_delete_t *f, const evlog_rec_t *r) {
    return f && r && r->type >= EVT_ALARM_RAISE && r->type <= EVT_ALARM_ACK && r->seq <= f->through_seq &&
           (!f->seq || r->seq == f->seq) && (f->dev < 0 || r->dev == (uint16_t)f->dev) &&
           (f->min_sev < 0 || r->sev >= (uint8_t)f->min_sev) &&
           (!f->from_s || (r->ts && r->ts >= f->from_s)) && (!f->to_s || (r->ts && r->ts <= f->to_s));
}
esp_err_t evlog_files_delete_alarms(evlog_files_t *files, const evlog_delete_t *filter, uint32_t *deleted) {
    *deleted = 0;
    for (unsigned i = 0; i < 2; i++) {
        FILE *src = fopen(files->path[i], "rb");
        if (!src) {
            if (errno != ENOENT)
                return ESP_FAIL;
            continue;
        }
        evlog_rec_t probe;
        bool match = false;
        while (fread(&probe, sizeof(probe), 1, src) == 1) {
            if (evlog_delete_match(filter, &probe)) {
                match = true;
                break;
            }
        }
        if (ferror(src)) {
            fclose(src);
            return ESP_FAIL;
        }
        if (!match) {
            fclose(src);
            continue;
        }
        rewind(src);
        char temp[EVLOG_PATH_SZ + 8];
        snprintf(temp, sizeof(temp), "%s.delete", files->path[i]);
        FILE *dst = fopen(temp, "wb");
        if (!dst) {
            fclose(src);
            return ESP_FAIL;
        }
        evlog_rec_t r;
        uint32_t kept = 0, removed = 0;
        bool ok = true;
        while (fread(&r, sizeof(r), 1, src) == 1) {
            if (evlog_delete_match(filter, &r))
                removed++;
            else if (fwrite(&r, sizeof(r), 1, dst) != 1) {
                ok = false;
                break;
            } else
                kept++;
        }
        if (ferror(src))
            ok = false;
        fclose(src);
        if (fflush(dst) != 0 || fsync(fileno(dst)) != 0)
            ok = false;
        if (fclose(dst) != 0)
            ok = false;
        if (!ok || rename(temp, files->path[i]) != 0) {
            remove(temp);
            return ESP_FAIL;
        }
        files->count[i] = kept;
        *deleted += removed;
    }
    return ESP_OK;
}

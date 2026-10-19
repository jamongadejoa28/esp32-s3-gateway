/* WebSocket endpoint /ws and broadcast hub (web/ws_hub.h, docs/API.md §5).
 *
 * Threading: frames are built once per event in gw_evt handlers (registered here) into pool
 * buffers (PSRAM) and handed to the httpd task with httpd_queue_work(); all socket I/O happens in
 * the httpd task (send_work, handshake callback, frame handler, close hook). The client table and
 * the pool are guarded by one leaf mutex; nothing else is called while it is held. */
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>

#include "alarm/alarm.h"
#include "auth/auth.h"
#include "esp_heap_caps.h"
#include "esp_attr.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "gw_core/gw_events.h"
#include "gw_core/gw_time.h"
#include "mex150/model.h"
#include "mex150/poll_plan.h"
#include "mex150/regmap.h"
#include "mex150/service.h"
#include "net/net.h"
#include "sdkconfig.h"
#include "store/config.h"
#include "web/web_path.h"
#include "web/ws_hub.h"
#include "web_priv.h"

static const char *TAG = "ws_hub";

static_assert(WS_T_SNAP == WS_TOPIC_SNAP_BIT && WS_T_ALARM == WS_TOPIC_ALARM_BIT &&
                  WS_T_COMM == WS_TOPIC_COMM_BIT && WS_T_WRITE == WS_TOPIC_WRITE_BIT &&
                  WS_T_SYS == WS_TOPIC_SYS_BIT,
              "topic bits");
static_assert(MEX_REG_COUNT <= WS_SNAP_MAX_REGS, "snap register capacity");

#define TARGET_ALL (-1)       /* broadcast to subscribed clients */
#define TARGET_ALL_CLOSE (-2) /* every client, then close (reboot) */
#define SESSION_SWEEP_S 5
#define CLOSE_NORMAL 1000
#define CLOSE_TOO_BIG 1009
/* A broadcast never blocks the httpd task on a client whose TCP window is closed (phone asleep or out
 * of AP range): such a client skips the periodic, self-healing frames (snap/comm/sys; a full snap is
 * requested when it drains) and is dropped when an event frame (alarm/write) would have to wait or
 * after WS_STALL_DROP_MS of continuous stall. Each blocked send would otherwise hold every dashboard,
 * REST call and the HTTPD heartbeat for up to send_wait_timeout. */
#define WS_STALL_DROP_MS 10000u
#define WS_SKIPPABLE_TOPICS (WS_T_SNAP | WS_T_COMM | WS_T_SYS)

/* Every queued frame holds one slot of httpd's control mailbox (CONFIG_LWIP_UDP_RECVMBOX_SIZE,
 * shared with the heartbeat, async-request completions of both worker lanes and session closes).
 * Keep WS_MBOX_RESERVE slots free for those so broadcasts never starve them. */
#define WS_MBOX_RESERVE 3
static_assert(CONFIG_LWIP_UDP_RECVMBOX_SIZE > WS_MBOX_RESERVE + 1, "control mailbox too small");
#define WS_INFLIGHT_MAX                                                                                       \
    (WS_FRAME_POOL < CONFIG_LWIP_UDP_RECVMBOX_SIZE - WS_MBOX_RESERVE ? WS_FRAME_POOL                         \
                                                                       : CONFIG_LWIP_UDP_RECVMBOX_SIZE - WS_MBOX_RESERVE)

typedef struct {
    int fd; /* -1 = free */
    auth_sid_t sid;
    uint32_t topics;
    bool subscribed;
    bool active;       /* hello sent */
    uint32_t stall_ms; /* mono ms (| 1) of the first broadcast skipped for a full send buffer, 0 = none */
} ws_client_t;

typedef struct {
    bool used;
    int target;       /* fd, TARGET_ALL or TARGET_ALL_CLOSE */
    auth_sid_t sid;   /* fd targets: only a client of this session (0 = any) */
    bool close_after;
    uint32_t topics;
    size_t len;
    char *data; /* WS_FRAME_MAX bytes */
} ws_buf_t;

static SemaphoreHandle_t s_mtx;
static StaticSemaphore_t s_mtx_buf;
static httpd_handle_t s_hd;
static ws_client_t s_cl[GW_MAX_WS_CLIENTS];
static ws_buf_t s_pool[WS_FRAME_POOL];
static uint32_t s_full_req; /* bit per device: send a full snap next */
static uint32_t s_dropped;
static bool s_ip_recheck; /* allowlist changed: re-check open sockets on the next tick (gw_evt only) */
static EXT_RAM_BSS_ATTR ws_snap_state_t s_snap[GW_MAX_DEVICES]; /* gw_evt task only (PSRAM) */
static esp_event_handler_instance_t s_inst[8];

static void lock(void) {
    xSemaphoreTake(s_mtx, portMAX_DELAY);
}

static void unlock(void) {
    xSemaphoreGive(s_mtx);
}

/* ---------------------------------------------------------------- pool */

static ws_buf_t *pool_get(void) {
    ws_buf_t *b = NULL;
    size_t in_use = 0;
    lock();
    for (size_t i = 0; i < WS_FRAME_POOL; i++) {
        in_use += s_pool[i].used ? 1u : 0u;
    }
    for (size_t i = 0; i < WS_FRAME_POOL && in_use < WS_INFLIGHT_MAX; i++) {
        if (!s_pool[i].used && s_pool[i].data) {
            b = &s_pool[i];
            b->used = true;
            b->sid = 0;
            break;
        }
    }
    if (!b) {
        s_dropped++;
    }
    unlock();
    return b;
}

static void pool_put(ws_buf_t *b) {
    lock();
    b->used = false;
    b->len = 0;
    unlock();
}

/* ---------------------------------------------------------------- socket I/O (httpd task) */

static esp_err_t send_text(int fd, const char *data, size_t len) {
    httpd_ws_frame_t f = {.final = true, .type = HTTPD_WS_TYPE_TEXT, .payload = (uint8_t *)data, .len = len};
    return httpd_ws_send_frame_async(s_hd, fd, &f);
}

static void send_close(int fd, uint16_t code) {
    uint8_t p[2] = {(uint8_t)(code >> 8), (uint8_t)code};
    httpd_ws_frame_t f = {.final = true, .type = HTTPD_WS_TYPE_CLOSE, .payload = p, .len = sizeof(p)};
    (void)httpd_ws_send_frame_async(s_hd, fd, &f);
}

static void forget_fd(int fd) {
    lock();
    for (size_t i = 0; i < GW_MAX_WS_CLIENTS; i++) {
        if (s_cl[i].fd == fd) {
            s_cl[i].fd = -1;
            s_cl[i].active = false;
            s_cl[i].subscribed = false;
            s_cl[i].topics = 0;
            s_cl[i].sid = 0;
            s_cl[i].stall_ms = 0;
        }
    }
    unlock();
}

/* True when the socket can take more data now. lwIP reports a TCP socket writable while more than
 * TCP_SNDLOWAT (about half of the send buffer) is free, i.e. the peer is acknowledging. */
static bool sock_writable(int fd) {
    fd_set w;
    FD_ZERO(&w);
    FD_SET(fd, &w);
    struct timeval tv = {0, 0};
    return select(fd + 1, NULL, &w, NULL, &tv) > 0 && FD_ISSET(fd, &w);
}

/* Record a skipped broadcast for fd; returns the stall start (mono ms | 1). */
static uint32_t stall_mark(int fd, uint32_t now) {
    uint32_t since = now | 1u;
    lock();
    for (size_t i = 0; i < GW_MAX_WS_CLIENTS; i++) {
        if (s_cl[i].fd == fd) {
            if (!s_cl[i].stall_ms) {
                s_cl[i].stall_ms = since;
            }
            since = s_cl[i].stall_ms;
        }
    }
    unlock();
    return since;
}

static void stall_clear(int fd) {
    lock();
    for (size_t i = 0; i < GW_MAX_WS_CLIENTS; i++) {
        if (s_cl[i].fd == fd) {
            s_cl[i].stall_ms = 0;
        }
    }
    unlock();
}

/* Close one client: optional bye, close frame, socket close (queued by httpd). */
static void drop_client(int fd, const char *bye_reason, uint16_t code) {
    if (bye_reason) {
        char buf[64];
        gw_jw_t w;
        gw_jw_init_fixed(&w, buf, sizeof(buf));
        ws_frame_bye(&w, bye_reason);
        if (gw_jw_finish(&w) == GW_JW_OK) {
            (void)send_text(fd, gw_jw_data(&w), gw_jw_length(&w));
        }
    }
    send_close(fd, code);
    forget_fd(fd);
    web_close_fd(fd);
}

static void send_work(void *arg) {
    ws_buf_t *b = arg;
    if (!s_hd) {
        pool_put(b);
        return;
    }
    ws_client_t cl[GW_MAX_WS_CLIENTS];
    lock();
    memcpy(cl, s_cl, sizeof(cl));
    unlock();
    for (size_t i = 0; i < GW_MAX_WS_CLIENTS; i++) {
        const ws_client_t *c = &cl[i];
        if (c->fd < 0) {
            continue;
        }
        if (b->target >= 0) {
            /* Same fd AND same session: the socket may have been closed and its number reused by a
             * new client of another session between queueing and now. */
            if (c->fd != b->target || (b->sid && c->sid != b->sid)) {
                continue;
            }
        } else if (b->target == TARGET_ALL) {
            if (!c->active || !c->subscribed || !(c->topics & b->topics)) {
                continue;
            }
            if (auth_session_check(c->sid, NULL) != AUTH_OK) {
                drop_client(c->fd, WS_BYE_SESSION_EXPIRED, CLOSE_NORMAL);
                continue;
            }
        }
        if (httpd_ws_get_fd_info(s_hd, c->fd) != HTTPD_WS_CLIENT_WEBSOCKET) {
            continue; /* handshake not finished or socket gone: close_fn cleans up */
        }
        if (b->target == TARGET_ALL) {
            if (!sock_writable(c->fd)) {
                const uint32_t now = (uint32_t)gw_time_mono_ms();
                const uint32_t since = stall_mark(c->fd, now);
                const bool skippable = !b->close_after && !(b->topics & ~(uint32_t)WS_SKIPPABLE_TOPICS);
                if (!skippable || now - since >= WS_STALL_DROP_MS) {
                    /* No bye/close frame: it could only block on the full buffer as well. */
                    ESP_LOGW(TAG, "fd %d not draining for %u ms: dropping client", c->fd, (unsigned)(now - since));
                    forget_fd(c->fd);
                    web_close_fd(c->fd);
                }
                continue;
            }
            if (c->stall_ms) {
                stall_clear(c->fd);
                /* it missed deltas: full snaps next (harmless for the others) */
                __atomic_or_fetch(&s_full_req, (1u << GW_MAX_DEVICES) - 1u, __ATOMIC_SEQ_CST);
            }
        }
        if (send_text(c->fd, b->data, b->len) != ESP_OK) {
            ESP_LOGW(TAG, "send to fd %d failed: dropping client", c->fd);
            send_close(c->fd, CLOSE_NORMAL);
            forget_fd(c->fd);
            web_close_fd(c->fd);
            continue;
        }
        if (b->close_after || b->target == TARGET_ALL_CLOSE) {
            send_close(c->fd, CLOSE_NORMAL);
            forget_fd(c->fd);
            web_close_fd(c->fd);
        }
    }
    pool_put(b);
}

/* Hand a filled pool buffer to the httpd task. */
static esp_err_t queue_buf(ws_buf_t *b) {
    httpd_handle_t hd = s_hd;
    if (!hd || httpd_queue_work(hd, send_work, b) != ESP_OK) {
        lock();
        s_dropped++;
        unlock();
        pool_put(b);
        return ESP_FAIL;
    }
    return ESP_OK;
}

static esp_err_t queue_copy(int target, auth_sid_t sid, uint32_t topics, bool close_after, const char *json,
                            size_t len) {
    if (!s_mtx || !s_hd || !json || !len || len > WS_FRAME_MAX) {
        return ESP_ERR_INVALID_ARG;
    }
    ws_buf_t *b = pool_get();
    if (!b) {
        return ESP_ERR_NO_MEM;
    }
    memcpy(b->data, json, len);
    b->len = len;
    b->target = target;
    b->sid = sid;
    b->topics = topics;
    b->close_after = close_after;
    return queue_buf(b) == ESP_OK ? ESP_OK : ESP_FAIL;
}

/* ---------------------------------------------------------------- public API */

esp_err_t ws_hub_broadcast(uint32_t topics, const char *json, size_t len) {
    return queue_copy(TARGET_ALL, 0, topics, false, json, len);
}

esp_err_t ws_hub_send_to(int sockfd, const char *json, size_t len) {
    if (sockfd < 0) {
        return ESP_ERR_INVALID_ARG;
    }
    return queue_copy(sockfd, 0, 0, false, json, len);
}

static void bye_json(const char *reason, char *buf, size_t cap, size_t *len) {
    gw_jw_t w;
    gw_jw_init_fixed(&w, buf, cap);
    ws_frame_bye(&w, reason);
    *len = gw_jw_finish(&w) == GW_JW_OK ? gw_jw_length(&w) : 0;
}

void ws_hub_close_session(auth_sid_t sid, const char *reason) {
    if (!s_mtx || !sid) {
        return;
    }
    int fds[GW_MAX_WS_CLIENTS];
    size_t n = 0;
    lock();
    for (size_t i = 0; i < GW_MAX_WS_CLIENTS; i++) {
        if (s_cl[i].fd >= 0 && s_cl[i].sid == sid) {
            fds[n++] = s_cl[i].fd;
        }
    }
    unlock();
    char buf[64];
    size_t len = 0;
    bye_json(reason, buf, sizeof(buf), &len);
    for (size_t i = 0; i < n && len; i++) {
        (void)queue_copy(fds[i], sid, 0, true, buf, len);
    }
}

void ws_hub_close_all(const char *reason) {
    char buf[64];
    size_t len = 0;
    bye_json(reason, buf, sizeof(buf), &len);
    if (len) {
        (void)queue_copy(TARGET_ALL_CLOSE, 0, 0, true, buf, len);
    }
}

uint32_t ws_hub_topics(void) {
    if (!s_mtx) {
        return 0;
    }
    uint32_t t = 0;
    lock();
    for (size_t i = 0; i < GW_MAX_WS_CLIENTS; i++) {
        if (s_cl[i].fd >= 0 && s_cl[i].active && s_cl[i].subscribed) {
            t |= s_cl[i].topics;
        }
    }
    unlock();
    return t;
}

bool ws_hub_take_full_request(uint8_t dev) {
    if (dev >= 32) {
        return false;
    }
    uint32_t bit = 1u << dev;
    return (__atomic_fetch_and(&s_full_req, ~bit, __ATOMIC_SEQ_CST) & bit) != 0;
}

size_t ws_hub_client_count(void) {
    if (!s_mtx) {
        return 0;
    }
    size_t n = 0;
    lock();
    for (size_t i = 0; i < GW_MAX_WS_CLIENTS; i++) {
        n += s_cl[i].fd >= 0 ? 1u : 0u;
    }
    unlock();
    return n;
}

void ws_hub_on_close(int sockfd) {
    if (s_mtx) {
        forget_fd(sockfd);
    }
}

/* ---------------------------------------------------------------- handshake + frames (httpd task) */

static void hello_work(void *arg) {
    const int fd = (int)(intptr_t)arg;
    if (!s_hd || httpd_ws_get_fd_info(s_hd, fd) != HTTPD_WS_CLIENT_WEBSOCKET) {
        return;
    }
    cfg_modbus_t m;
    uint8_t devs[GW_MAX_DEVICES];
    uint32_t seqs[GW_MAX_DEVICES];
    size_t n = 0;
    if (cfg_get_section(CFG_SEC_MODBUS, &m, sizeof(m)) == ESP_OK) {
        for (size_t i = 0; i < m.n_devices && i < GW_MAX_DEVICES; i++) {
            if (!m.devices[i].enabled) {
                continue;
            }
            mex_snapshot_t s;
            devs[n] = m.devices[i].id;
            seqs[n] = mex_service_snapshot(m.devices[i].id, &s) ? s.seq : 0;
            n++;
        }
    }
    char buf[256];
    gw_jw_t w;
    gw_jw_init_fixed(&w, buf, sizeof(buf));
    ws_frame_hello(&w, gw_time_valid() ? gw_time_wall_ms() : 0, devs, seqs, n, web_meta_etag());
    if (gw_jw_finish(&w) != GW_JW_OK || send_text(fd, gw_jw_data(&w), gw_jw_length(&w)) != ESP_OK) {
        ESP_LOGW(TAG, "hello to fd %d failed", fd);
        forget_fd(fd);
        web_close_fd(fd);
        return;
    }
    lock();
    for (size_t i = 0; i < GW_MAX_WS_CLIENTS; i++) {
        if (s_cl[i].fd == fd) {
            s_cl[i].active = true;
        }
    }
    unlock();
}

static esp_err_t pre_handshake(httpd_req_t *req) {
    web_rstate_t rs;
    memset(&rs, 0, sizeof(rs));
    rs.api = true;
    req->user_ctx = &rs;
    esp_err_t ret = ESP_FAIL;
    if (!net_ip_allowed_fd(httpd_req_to_sockfd(req))) {
        goto out; /* allowlist narrowed since the connection opened: close without an answer */
    }
    if (!web_host_check(req)) { /* 421 sent */
        goto out;
    }
    char *hbuf = malloc(512 + 256 + 96);
    if (!hbuf) {
        web_send_error_raw(req, 503, WEB_E_UNAVAILABLE);
        goto out;
    }
    char *cookie = hbuf;
    char *origin = hbuf + 512;
    char *host = origin + 256;
    char token[AUTH_TOKEN_SZ + 8];
    auth_session_info_t info;
    const size_t cl = httpd_req_get_hdr_value_len(req, "Cookie");
    bool authed = cl && cl < 512 && httpd_req_get_hdr_value_str(req, "Cookie", cookie, 512) == ESP_OK &&
                  web_cookie_get(cookie, AUTH_COOKIE_NAME, token, sizeof(token)) &&
                  auth_session_lookup(token, false, &info) == AUTH_OK;
    memset(token, 0, sizeof(token));
    if (!authed) {
        web_send_error_raw(req, 401, WEB_E_UNAUTHORIZED);
        free(hbuf);
        goto out;
    }
    if (info.must_change) {
        web_send_error_raw(req, 403, WEB_E_PASSWORD_CHANGE);
        free(hbuf);
        goto out;
    }
    const size_t ol = httpd_req_get_hdr_value_len(req, "Origin");
    if (ol) {
        host[0] = '\0';
        size_t hl = httpd_req_get_hdr_value_len(req, "Host");
        bool ok = ol < 256 && hl && hl < 96 &&
                  httpd_req_get_hdr_value_str(req, "Origin", origin, 256) == ESP_OK &&
                  httpd_req_get_hdr_value_str(req, "Host", host, 96) == ESP_OK &&
                  web_origin_matches_host(origin, host);
        if (!ok) {
            web_send_error_raw(req, 403, WEB_E_ORIGIN);
            free(hbuf);
            goto out;
        }
    }
    free(hbuf);
    const int fd = httpd_req_to_sockfd(req);
    bool slot = false;
    lock();
    for (size_t i = 0; i < GW_MAX_WS_CLIENTS && !slot; i++) {
        if (s_cl[i].fd == fd) {
            slot = true; /* re-handshake on the same socket: reuse */
            s_cl[i].sid = info.sid;
        }
    }
    for (size_t i = 0; i < GW_MAX_WS_CLIENTS && !slot; i++) {
        if (s_cl[i].fd < 0) {
            s_cl[i] = (ws_client_t){.fd = fd, .sid = info.sid};
            slot = true;
        }
    }
    unlock();
    memset(&info, 0, sizeof(info));
    if (!slot) {
        web_send_error_raw(req, 503, WEB_E_UNAVAILABLE);
        goto out;
    }
    if (httpd_queue_work(req->handle, hello_work, (void *)(intptr_t)fd) != ESP_OK) {
        forget_fd(fd);
        web_send_error_raw(req, 503, WEB_E_UNAVAILABLE);
        goto out;
    }
    ret = ESP_OK;
out:
    req->user_ctx = NULL;
    return ret;
}

static esp_err_t ws_handler(httpd_req_t *req) {
    const int fd = httpd_req_to_sockfd(req);
    if (httpd_ws_get_fd_info(req->handle, fd) != HTTPD_WS_CLIENT_WEBSOCKET) {
        /* GET /ws without an Upgrade: not a WebSocket request. */
        web_rstate_t rs;
        memset(&rs, 0, sizeof(rs));
        rs.api = true;
        req->user_ctx = &rs;
        if (web_host_check(req)) {
            web_send_error_raw(req, 400, WEB_E_BAD_REQUEST);
        }
        req->user_ctx = NULL;
        return ESP_OK;
    }
    httpd_ws_frame_t f;
    memset(&f, 0, sizeof(f));
    esp_err_t err = httpd_ws_recv_frame(req, &f, 0);
    if (err != ESP_OK) {
        return err;
    }
    if (f.len > WS_RX_MAX) {
        ESP_LOGW(TAG, "fd %d sent a %u byte frame: closing (1009)", fd, (unsigned)f.len);
        send_close(fd, CLOSE_TOO_BIG);
        forget_fd(fd);
        return ESP_FAIL;
    }
    uint8_t buf[WS_RX_MAX + 1];
    f.payload = buf;
    if (f.len) {
        err = httpd_ws_recv_frame(req, &f, WS_RX_MAX);
        if (err != ESP_OK) {
            return err;
        }
    }
    if (f.type != HTTPD_WS_TYPE_TEXT || !f.len) {
        return ESP_OK; /* binary/pong/empty: ignored */
    }
    uint32_t topics = 0;
    switch (ws_parse_client((const char *)buf, f.len, &topics)) {
    case WS_MSG_SUB: {
        lock();
        for (size_t i = 0; i < GW_MAX_WS_CLIENTS; i++) {
            if (s_cl[i].fd == fd) {
                s_cl[i].topics = topics & WS_TOPIC_ALL;
                s_cl[i].subscribed = true;
            }
        }
        unlock();
        if (topics & WS_T_SNAP) {
            __atomic_or_fetch(&s_full_req, (1u << GW_MAX_DEVICES) - 1u, __ATOMIC_SEQ_CST);
        }
        break;
    }
    case WS_MSG_PING: {
        char out[48];
        gw_jw_t w;
        gw_jw_init_fixed(&w, out, sizeof(out));
        ws_frame_pong(&w, gw_time_valid() ? gw_time_wall_ms() : 0);
        if (gw_jw_finish(&w) == GW_JW_OK) {
            httpd_ws_frame_t p = {.final = true,
                                  .type = HTTPD_WS_TYPE_TEXT,
                                  .payload = (uint8_t *)out,
                                  .len = gw_jw_length(&w)};
            err = httpd_ws_send_frame(req, &p);
        }
        break;
    }
    default:
        break; /* unknown messages are ignored (API.md §5) */
    }
    return err;
}

/* ---------------------------------------------------------------- frame builders (gw_evt task) */

static bool is_slow_reg(uint16_t addr) {
    for (size_t i = 0; i < MEX_SLOW_BLOCKS; i++) {
        unsigned first = MEX_ADDR_BASE + 1u + mex_slow_blocks[i].start;
        if (addr >= first && addr < first + mex_slow_blocks[i].count) {
            return true;
        }
    }
    return false;
}

/* Build into a pool buffer with fn(w, arg) and queue it for `topics`. */
static void emit(uint32_t topics, void (*fn)(gw_jw_t *w, const void *arg), const void *arg) {
    ws_buf_t *b = pool_get();
    if (!b) {
        return;
    }
    gw_jw_t w;
    gw_jw_init_fixed(&w, b->data, WS_FRAME_MAX);
    fn(&w, arg);
    if (gw_jw_finish(&w) != GW_JW_OK) {
        ESP_LOGW(TAG, "frame build error %d", gw_jw_error(&w));
        pool_put(b);
        return;
    }
    b->len = gw_jw_length(&w);
    b->target = TARGET_ALL;
    b->topics = topics;
    b->close_after = false;
    (void)queue_buf(b);
}

static void on_snapshot(const gw_evt_snapshot_t *ev) {
    if (ev->dev >= GW_MAX_DEVICES || !(ws_hub_topics() & WS_T_SNAP)) {
        return;
    }
    mex_snapshot_t s;
    if (!mex_service_snapshot(ev->dev, &s)) {
        return;
    }
    uint16_t addr[WS_SNAP_MAX_REGS];
    int32_t raw[WS_SNAP_MAX_REGS];
    size_t n = 0;
    for (size_t i = 0; i < MEX_REG_COUNT && n < WS_SNAP_MAX_REGS; i++) {
        const uint16_t a = mex_regs[i].addr;
        if (!s.slow_valid && is_slow_reg(a)) {
            continue;
        }
        addr[n] = a;
        raw[n] = mex_snap_raw(&s, a);
        n++;
    }
    const bool force = ws_hub_take_full_request(ev->dev);
    ws_buf_t *b = pool_get();
    if (!b) {
        s_snap[ev->dev].valid = false; /* a frame was lost: next one is full */
        return;
    }
    gw_jw_t w;
    gw_jw_init_fixed(&w, b->data, WS_FRAME_MAX);
    int rc = ws_frame_snap(&s_snap[ev->dev], &w, ev->dev, s.seq, s.wall_ms, s.online, addr, raw, n, s.coils,
                           force, gw_time_mono_ms(), WS_FULL_SNAP_S);
    if (rc != GW_JW_OK || gw_jw_finish(&w) != GW_JW_OK) {
        s_snap[ev->dev].valid = false;
        pool_put(b);
        return;
    }
    b->len = gw_jw_length(&w);
    b->target = TARGET_ALL;
    b->topics = WS_T_SNAP;
    b->close_after = false;
    if (queue_buf(b) != ESP_OK) {
        s_snap[ev->dev].valid = false;
    }
}

static void build_alarm(gw_jw_t *w, const void *arg) {
    const gw_evt_alarm_t *ev = arg;
    const alm_desc_t *d = alm_find_code(ev->code);
    ws_frame_alarm(w, ev->dev, d ? d->id : "unknown", ev->code, ev->type, ev->sev, ev->ts_ms, ev->seq,
                   ev->value, ev->user);
}

static void build_write(gw_jw_t *w, const void *arg) {
    const gw_evt_write_t *ev = arg;
    char reason[MEX_REASON_NAME_SZ];
    const bool applied = ev->state == MEX_W_APPLIED;
    ws_frame_write(w, ev->dev, ev->cmd, ev->addr, ev->state, ev->state != MEX_W_REJECTED, ev->raw_after,
                   applied ? NULL : mex_reason_name(ev->reason, reason, sizeof(reason)), ev->by);
}

typedef struct {
    uint8_t dev;
    bool online;
} comm_arg_t;

static void build_comm(gw_jw_t *w, const void *arg) {
    const comm_arg_t *a = arg;
    mex_stats_t st;
    mex_service_stats(a->dev, &st, false);
    ws_frame_comm(w, a->dev, a->online, st.rtt_last, st.crc, st.timeout, st.exception, st.malformed);
}

static void build_sys(gw_jw_t *w, const void *arg) {
    const gw_evt_tick_t *t = arg;
    uint16_t per_sev[4];
    uint32_t alarms = alarm_counts(per_sev);
    ws_frame_sys(w, (uint32_t)heap_caps_get_free_size(MALLOC_CAP_INTERNAL),
                 (uint32_t)heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL),
                 (uint32_t)heap_caps_get_free_size(MALLOC_CAP_SPIRAM), t->uptime_s,
                 t->time_valid ? t->wall_ms : 0, alarms);
}

/* httpd task: close every connection the (changed) IP allowlist no longer admits. WS clients get
 * bye "revoked" first; plain keep-alive connections are also refused per request by the router. */
static void ip_recheck_work(void *arg) {
    (void)arg;
    if (!s_hd) {
        return;
    }
    int fds[WEB_HTTPD_MAX_SOCKETS];
    size_t n = WEB_HTTPD_MAX_SOCKETS;
    if (httpd_get_client_list(s_hd, &n, fds) != ESP_OK) {
        ESP_LOGW(TAG, "allowlist re-check: client list unavailable");
        return;
    }
    for (size_t i = 0; i < n; i++) {
        if (net_ip_allowed_fd(fds[i])) {
            continue;
        }
        ESP_LOGI(TAG, "fd %d excluded by the new IP allowlist: closing", fds[i]);
        if (httpd_ws_get_fd_info(s_hd, fds[i]) == HTTPD_WS_CLIENT_WEBSOCKET) {
            drop_client(fds[i], WS_BYE_REVOKED, CLOSE_NORMAL);
        } else {
            forget_fd(fds[i]);
            web_close_fd(fds[i]);
        }
    }
}

/* Close clients whose session ended without a SESSION event reaching us (expiry is detected lazily). */
static void session_sweep(void) {
    ws_client_t cl[GW_MAX_WS_CLIENTS];
    lock();
    memcpy(cl, s_cl, sizeof(cl));
    unlock();
    for (size_t i = 0; i < GW_MAX_WS_CLIENTS; i++) {
        if (cl[i].fd >= 0 && cl[i].sid && auth_session_check(cl[i].sid, NULL) != AUTH_OK) {
            ws_hub_close_session(cl[i].sid, WS_BYE_SESSION_EXPIRED);
        }
    }
}

static void on_tick(const gw_evt_tick_t *t) {
    /* Allowlist re-check one tick after CONFIG_CHANGED{SECURITY}: gw_evt handles events in order, so
     * net's own CONFIG_CHANGED handler has installed the new filter by now. Retried while the
     * control mailbox is full. */
    if (s_ip_recheck && s_hd && httpd_queue_work(s_hd, ip_recheck_work, NULL) == ESP_OK) {
        s_ip_recheck = false;
    }
    if (t->uptime_s % SESSION_SWEEP_S == 0) {
        session_sweep();
    }
    const uint32_t topics = ws_hub_topics();
    if ((topics & WS_T_COMM) && t->uptime_s % WS_COMM_PERIOD_S == 0) {
        cfg_modbus_t m;
        if (cfg_get_section(CFG_SEC_MODBUS, &m, sizeof(m)) == ESP_OK) {
            for (size_t i = 0; i < m.n_devices && i < GW_MAX_DEVICES; i++) {
                if (!m.devices[i].enabled) {
                    continue;
                }
                mex_snapshot_t s;
                comm_arg_t a = {.dev = m.devices[i].id,
                                .online = mex_service_snapshot(m.devices[i].id, &s) && s.online};
                emit(WS_T_COMM, build_comm, &a);
            }
        }
    }
    if ((topics & WS_T_SYS) && t->uptime_s % WS_SYS_PERIOD_S == 0) {
        emit(WS_T_SYS, build_sys, t);
    }
}

static const char *session_reason(uint8_t kind) {
    switch (kind) {
    case GW_SESSION_LOGOUT:
        return WS_BYE_LOGOUT;
    case GW_SESSION_EXPIRED:
        return WS_BYE_SESSION_EXPIRED;
    default:
        return WS_BYE_REVOKED;
    }
}

static void on_event(void *arg, esp_event_base_t base, int32_t id, void *data) {
    (void)arg;
    (void)base;
    if (!data || !s_hd) {
        return;
    }
    switch (id) {
    case GW_EVT_SNAPSHOT:
        on_snapshot(data);
        break;
    case GW_EVT_ALARM:
        if (ws_hub_topics() & WS_T_ALARM) {
            emit(WS_T_ALARM, build_alarm, data);
        }
        break;
    case GW_EVT_WRITE_RESULT:
        if (ws_hub_topics() & WS_T_WRITE) {
            emit(WS_T_WRITE, build_write, data);
        }
        break;
    case GW_EVT_COMM: {
        const gw_evt_comm_t *ev = data;
        if (ws_hub_topics() & WS_T_COMM) {
            comm_arg_t a = {.dev = ev->dev, .online = ev->online};
            emit(WS_T_COMM, build_comm, &a);
        }
        break;
    }
    case GW_EVT_SYS_TICK:
        on_tick(data);
        break;
    case GW_EVT_SESSION: {
        const gw_evt_session_t *ev = data;
        if (ev->kind != GW_SESSION_LOGIN) {
            ws_hub_close_session(ev->sid, session_reason(ev->kind));
        }
        break;
    }
    case GW_EVT_REBOOT:
        ws_hub_close_all(WS_BYE_REBOOT);
        break;
    case GW_EVT_CONFIG_CHANGED: {
        const gw_evt_config_t *ev = data;
        if (ev->section == CFG_SEC_SECURITY) {
            s_ip_recheck = true;
        }
        break;
    }
    default:
        break;
    }
}

/* ---------------------------------------------------------------- lifecycle */

esp_err_t ws_hub_init(httpd_handle_t server) {
    if (!server) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!s_mtx) {
        s_mtx = xSemaphoreCreateMutexStatic(&s_mtx_buf);
        for (size_t i = 0; i < GW_MAX_WS_CLIENTS; i++) {
            s_cl[i].fd = -1;
        }
        for (size_t i = 0; i < WS_FRAME_POOL; i++) {
            s_pool[i].data = heap_caps_malloc_prefer(WS_FRAME_MAX, 2, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT,
                                                     MALLOC_CAP_DEFAULT);
            if (!s_pool[i].data) {
                ESP_LOGE(TAG, "frame pool allocation failed");
                return ESP_ERR_NO_MEM;
            }
        }
    }
    lock();
    for (size_t i = 0; i < GW_MAX_WS_CLIENTS; i++) {
        s_cl[i].fd = -1;
    }
    unlock();
    memset(s_snap, 0, sizeof(s_snap));
    const httpd_uri_t ws = {.uri = WS_PATH,
                            .method = HTTP_GET,
                            .handler = ws_handler,
                            .user_ctx = NULL,
                            .is_websocket = true,
                            .handle_ws_control_frames = false,
                            .ws_pre_handshake_cb = pre_handshake};
    esp_err_t err = httpd_register_uri_handler(server, &ws);
    if (err != ESP_OK) {
        return err;
    }
    s_hd = server;
    static const int32_t ids[] = {GW_EVT_SNAPSHOT, GW_EVT_ALARM,  GW_EVT_WRITE_RESULT, GW_EVT_COMM,
                                  GW_EVT_SYS_TICK, GW_EVT_SESSION, GW_EVT_REBOOT,      GW_EVT_CONFIG_CHANGED};
    static_assert(sizeof(ids) / sizeof(ids[0]) == sizeof(s_inst) / sizeof(s_inst[0]), "instances");
    for (size_t i = 0; i < sizeof(ids) / sizeof(ids[0]); i++) {
        if (s_inst[i]) {
            continue;
        }
        esp_err_t e = gw_events_register(ids[i], on_event, NULL, &s_inst[i]);
        if (e != ESP_OK) {
            ESP_LOGW(TAG, "event %d registration failed: %s (no live push)", (int)ids[i], esp_err_to_name(e));
            s_inst[i] = NULL;
        }
    }
    return ESP_OK;
}

void ws_hub_stop(void) {
    static const int32_t ids[] = {GW_EVT_SNAPSHOT, GW_EVT_ALARM,  GW_EVT_WRITE_RESULT, GW_EVT_COMM,
                                  GW_EVT_SYS_TICK, GW_EVT_SESSION, GW_EVT_REBOOT,      GW_EVT_CONFIG_CHANGED};
    for (size_t i = 0; i < sizeof(ids) / sizeof(ids[0]); i++) {
        if (s_inst[i]) {
            (void)gw_events_unregister(ids[i], s_inst[i]);
            s_inst[i] = NULL;
        }
    }
    s_hd = NULL;
    if (s_mtx) {
        lock();
        for (size_t i = 0; i < GW_MAX_WS_CLIENTS; i++) {
            s_cl[i].fd = -1;
        }
        unlock();
    }
}

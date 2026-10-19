/* HTTP server lifecycle (web/web.h): httpd configuration per DESIGN.md §4, wildcard handlers into
 * the router, IP allowlist in open_fn, WS cleanup in close_fn, httpd error hooks with JSON bodies
 * and security headers, the async worker for WEB_RF_SLOW routes, and the HTTPD heartbeat. */
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "gw_core/gw_crypto.h"
#include "gw_core/gw_health.h"
#include "net/net.h"
#include "web/web.h"
#include "web/ws_hub.h"
#include "web_priv.h"

static const char *TAG = "web";

#define HB_PERIOD_US (2000 * 1000)
#define ASYNC_QUEUE_LEN 4 /* admitted jobs per lane (queued + running) */
#define ASYNC_TASK_STACK 6144
#define ASYNC_TASK_PRIO 5
#define ASYNC_TASK_CORE 0
#define STOP_WAIT_MS 5000

typedef struct {
    httpd_req_t *req; /* async copy (httpd_req_async_handler_begin) */
    int fd;           /* socket, captured on the httpd task */
    web_ctx_t ctx;
    web_rstate_t rs;
} async_job_t;

/* Two async lanes so unauthenticated login traffic (PBKDF2 + the global 1 s delay) can never
 * queue in front of authenticated control actions (register write, run/stop, user admin):
 *   LOGIN   - WEB_RF_SLOW routes with min_role GW_ROLE_NONE (POST /auth/login)
 *   CONTROL - every other WEB_RF_SLOW route (an authenticated session is required)
 * Admission (inflight < ASYNC_QUEUE_LEN) is decided on the httpd task BEFORE
 * httpd_req_async_handler_begin(): the httpd task is the only producer and the queue holds
 * ASYNC_QUEUE_LEN items, so an admitted job always fits and the httpd task never has to undo a
 * begin with httpd_req_async_handler_complete() (that call waits with portMAX_DELAY for a control
 * mailbox slot which only the httpd task itself frees: self-deadlock). */
typedef enum { LANE_LOGIN = 0, LANE_CONTROL, LANE_COUNT } lane_id_t;

typedef struct {
    const char *name;
    QueueHandle_t q;
    TaskHandle_t task;
    uint32_t inflight; /* ++ on the httpd task at admission, -- by the worker after completion */
} lane_t;

static httpd_handle_t s_server;
static esp_timer_handle_t s_hb_timer;
static lane_t s_lane[LANE_COUNT] = {{.name = "httpd_login"}, {.name = "httpd_async"}};
static int s_rejected_fd = -1; /* fd refused by on_open: IDF closes it itself (httpd task only) */

httpd_handle_t web_httpd(void) {
    return s_server;
}

void *web_server_handle(void) {
    return s_server;
}

bool web_running(void) {
    return s_server != NULL;
}

/* ---------------------------------------------------------------- session hooks */

static esp_err_t on_open(httpd_handle_t hd, int sockfd) {
    (void)hd;
    if (!net_ip_allowed_fd(sockfd)) {
        ESP_LOGD(TAG, "connection on fd %d refused by the IP allowlist", sockfd);
        /* httpd_sess_new() now runs close_fn via httpd_sess_delete() and then httpd_accept_conn()
         * closes the fd itself: on_close must not close it a second time (the number may already
         * belong to another socket by then). */
        s_rejected_fd = sockfd;
        return ESP_FAIL;
    }
    return ESP_OK;
}

static void on_close(httpd_handle_t hd, int sockfd) {
    (void)hd;
    ws_hub_on_close(sockfd);
    if (sockfd == s_rejected_fd) {
        s_rejected_fd = -1; /* httpd_accept_conn() closes it */
        return;
    }
    close(sockfd); /* with a custom close_fn httpd leaves closing to us */
}

void web_close_fd(int sockfd) {
    httpd_handle_t hd = s_server;
    if (sockfd < 0) {
        return;
    }
    if (hd && httpd_sess_trigger_close(hd, sockfd) == ESP_OK) {
        return;
    }
    /* Control mailbox full (or no session): half-close instead. The FIN makes the peer close, httpd
     * then reads EOF on its next select pass and deletes the session through close_fn. */
    ESP_LOGW(TAG, "close of fd %d not queued: shutting the socket down", sockfd);
    (void)shutdown(sockfd, SHUT_WR);
}

/* ---------------------------------------------------------------- handlers */

static esp_err_t any_handler(httpd_req_t *req) {
    return web_router_dispatch(req);
}

static esp_err_t err_handler(httpd_req_t *req, httpd_err_code_t error) {
    web_rstate_t rs;
    memset(&rs, 0, sizeof(rs));
    rs.api = true;
    req->user_ctx = &rs;
    int status = 500;
    const char *code = WEB_E_INTERNAL;
    switch (error) {
    case HTTPD_400_BAD_REQUEST:
    case HTTPD_411_LENGTH_REQUIRED:
    case HTTPD_414_URI_TOO_LONG:
    case HTTPD_431_REQ_HDR_FIELDS_TOO_LARGE:
    case HTTPD_505_VERSION_NOT_SUPPORTED:
        status = 400;
        code = WEB_E_BAD_REQUEST;
        break;
    case HTTPD_404_NOT_FOUND:
    case HTTPD_405_METHOD_NOT_ALLOWED:
    case HTTPD_501_METHOD_NOT_IMPLEMENTED:
        status = 404; /* default-deny: unknown method/route is "not found" */
        code = WEB_E_NOT_FOUND;
        break;
    case HTTPD_408_REQ_TIMEOUT:
        status = 408;
        code = WEB_E_BAD_REQUEST;
        break;
    case HTTPD_413_CONTENT_TOO_LARGE:
        status = 413;
        code = WEB_E_TOO_LARGE;
        break;
    default:
        break;
    }
    web_send_error_raw(req, status, code);
    /* Parse errors leave the stream in an unknown state: close the connection (httpd default). */
    return ESP_FAIL;
}

/* ---------------------------------------------------------------- async workers */

static void async_task(void *arg) {
    lane_t *lane = arg;
    for (;;) {
        async_job_t *job = NULL;
        if (xQueueReceive(lane->q, &job, portMAX_DELAY) != pdTRUE || !job) {
            continue;
        }
        job->req->user_ctx = &job->rs;
        job->ctx.req = job->req;
        const bool close_conn = web_router_run_handler(&job->ctx);
        if (job->ctx.body) {
            gw_secure_zero(job->ctx.body, job->ctx.body_len); /* may carry passwords */
            free(job->ctx.body);
        }
        web_rstate_cleanup(&job->rs);
        if (close_conn && job->fd >= 0) {
            /* Truncated stream: half-close while this task still owns the socket; once completed,
             * httpd reads EOF on it and deletes the session (no control-mailbox slot needed). */
            (void)shutdown(job->fd, SHUT_WR);
        }
        /* May wait for a control-mailbox slot: fine here, the httpd task drains the mailbox and never
         * waits for this task. */
        if (httpd_req_async_handler_complete(job->req) != ESP_OK) {
            ESP_LOGW(TAG, "%s: async completion failed", lane->name);
        }
        memset(job, 0, sizeof(*job)); /* session info incl. CSRF token */
        free(job);
        __atomic_sub_fetch(&lane->inflight, 1, __ATOMIC_SEQ_CST);
    }
}

esp_err_t web_async_submit(httpd_req_t *req, const web_ctx_t *ctx) {
    lane_t *lane = &s_lane[ctx->route && ctx->route->min_role == GW_ROLE_NONE ? LANE_LOGIN : LANE_CONTROL];
    if (!lane->q) {
        return ESP_ERR_INVALID_STATE;
    }
    /* Admission first (httpd task = only producer): nothing below can fail after begin(). */
    if (__atomic_load_n(&lane->inflight, __ATOMIC_SEQ_CST) >= ASYNC_QUEUE_LEN) {
        ESP_LOGW(TAG, "%s busy", lane->name);
        return ESP_ERR_NO_MEM;
    }
    async_job_t *job = calloc(1, sizeof(*job));
    if (!job) {
        return ESP_ERR_NO_MEM;
    }
    if (httpd_req_async_handler_begin(req, &job->req) != ESP_OK) {
        free(job);
        return ESP_FAIL;
    }
    job->fd = httpd_req_to_sockfd(req);
    job->ctx = *ctx;
    job->rs.api = true;
    __atomic_add_fetch(&lane->inflight, 1, __ATOMIC_SEQ_CST);
    /* Queued items <= inflight <= ASYNC_QUEUE_LEN = queue length, so this never waits. */
    (void)xQueueSend(lane->q, &job, portMAX_DELAY);
    return ESP_OK;
}

static uint32_t async_inflight(void) {
    uint32_t n = 0;
    for (size_t i = 0; i < LANE_COUNT; i++) {
        n += __atomic_load_n(&s_lane[i].inflight, __ATOMIC_SEQ_CST);
    }
    return n;
}

static esp_err_t async_init(void) {
    for (size_t i = 0; i < LANE_COUNT; i++) {
        lane_t *lane = &s_lane[i];
        if (lane->q) {
            continue;
        }
        lane->q = xQueueCreate(ASYNC_QUEUE_LEN, sizeof(async_job_t *));
        if (!lane->q) {
            return ESP_ERR_NO_MEM;
        }
        if (xTaskCreatePinnedToCore(async_task, lane->name, ASYNC_TASK_STACK, lane, ASYNC_TASK_PRIO, &lane->task,
                                    ASYNC_TASK_CORE) != pdPASS) {
            vQueueDelete(lane->q);
            lane->q = NULL;
            return ESP_ERR_NO_MEM;
        }
    }
    return ESP_OK;
}

/* ---------------------------------------------------------------- heartbeat */

static void hb_work(void *arg) {
    (void)arg;
    gw_hb_beat(GW_HB_HTTPD);
}

static void hb_timer_cb(void *arg) {
    (void)arg;
    httpd_handle_t hd = s_server;
    if (hd) {
        (void)httpd_queue_work(hd, hb_work, NULL); /* non-blocking; a miss is just a late beat */
    }
}

/* ---------------------------------------------------------------- lifecycle */

esp_err_t web_start(void) {
    if (s_server) {
        return ESP_ERR_INVALID_STATE;
    }
    web_cjson_hooks_install();
    esp_err_t err = web_router_register(web_api_routes, web_api_routes_count);
    if (err != ESP_OK) {
        return err;
    }
    err = web_api_config_init();
    if (err != ESP_OK) {
        return err;
    }
    err = async_init();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "async worker: %s", esp_err_to_name(err));
        return err;
    }

    httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
    cfg.server_port = WEB_HTTP_PORT;
    cfg.task_priority = 5;
    cfg.stack_size = 8192;
    cfg.core_id = 0;
    cfg.max_uri_handlers = 8;
    cfg.max_open_sockets = WEB_HTTPD_MAX_SOCKETS;
    cfg.max_resp_headers = 12;
    cfg.lru_purge_enable = true;
    cfg.keep_alive_enable = true;
    cfg.keep_alive_idle = 5;
    cfg.keep_alive_interval = 5;
    cfg.keep_alive_count = 3;
    /* SO_SNDTIMEO of every socket: bounds how long one stalled peer can hold the single httpd task
     * (WS broadcasts additionally skip clients whose buffer is full, ws_hub.c). Two stalls in a row
     * stay below GW_HB_MAX_AGE_MS. */
    cfg.send_wait_timeout = 1;
    cfg.recv_wait_timeout = 5;
    cfg.open_fn = on_open;
    cfg.close_fn = on_close;
    cfg.uri_match_fn = httpd_uri_match_wildcard;

    httpd_handle_t hd = NULL;
    err = httpd_start(&hd, &cfg);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "httpd_start: %s", esp_err_to_name(err));
        return err;
    }
    /* /ws first: handlers match in registration order and the wildcard would swallow it. */
    err = ws_hub_init(hd);
    static const httpd_method_t methods[] = {HTTP_GET, HTTP_POST, HTTP_PUT, HTTP_DELETE};
    for (size_t i = 0; err == ESP_OK && i < sizeof(methods) / sizeof(methods[0]); i++) {
        const httpd_uri_t u = {.uri = "/*", .method = methods[i], .handler = any_handler, .user_ctx = NULL};
        err = httpd_register_uri_handler(hd, &u);
    }
    static const httpd_err_code_t errs[] = {HTTPD_400_BAD_REQUEST,
                                            HTTPD_404_NOT_FOUND,
                                            HTTPD_405_METHOD_NOT_ALLOWED,
                                            HTTPD_408_REQ_TIMEOUT,
                                            HTTPD_411_LENGTH_REQUIRED,
                                            HTTPD_413_CONTENT_TOO_LARGE,
                                            HTTPD_414_URI_TOO_LONG,
                                            HTTPD_431_REQ_HDR_FIELDS_TOO_LARGE,
                                            HTTPD_501_METHOD_NOT_IMPLEMENTED,
                                            HTTPD_505_VERSION_NOT_SUPPORTED};
    for (size_t i = 0; err == ESP_OK && i < sizeof(errs) / sizeof(errs[0]); i++) {
        err = httpd_register_err_handler(hd, errs[i], err_handler);
    }
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "handler registration: %s", esp_err_to_name(err));
        ws_hub_stop();
        httpd_stop(hd);
        return err;
    }
    s_server = hd;

    if (!s_hb_timer) {
        const esp_timer_create_args_t ta = {.callback = hb_timer_cb, .name = "web_hb"};
        err = esp_timer_create(&ta, &s_hb_timer);
    }
    if (err == ESP_OK) {
        err = esp_timer_start_periodic(s_hb_timer, HB_PERIOD_US);
    }
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "heartbeat timer: %s", esp_err_to_name(err));
        web_stop(false);
        return err;
    }
    gw_hb_beat(GW_HB_HTTPD);
    ESP_LOGI(TAG, "HTTP server on port %d", WEB_HTTP_PORT);
    return ESP_OK;
}

esp_err_t web_stop(bool rebooting) {
    httpd_handle_t hd = s_server;
    if (!hd) {
        return ESP_ERR_INVALID_STATE;
    }
    if (s_hb_timer) {
        esp_timer_stop(s_hb_timer);
    }
    ws_hub_close_all(rebooting ? WS_BYE_REBOOT : WS_BYE_SESSION_EXPIRED);
    vTaskDelay(pdMS_TO_TICKS(200)); /* let the queued bye frames go out */
    for (int waited = 0; async_inflight() && waited < STOP_WAIT_MS; waited += 50) {
        vTaskDelay(pdMS_TO_TICKS(50));
    }
    ws_hub_stop();
    s_server = NULL;
    esp_err_t err = httpd_stop(hd);
    ESP_LOGI(TAG, "HTTP server stopped");
    return err;
}

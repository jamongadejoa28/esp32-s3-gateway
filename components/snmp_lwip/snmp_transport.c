/* Single-thread SNMP transport replacing upstream snmp_netconn.c (contract: snmp_transport.h).
 *
 * One agent task owns the UDP/161 netconn and is the ONLY context that calls into the lwIP SNMP
 * agent (snmp_receive, snmp_set_*, snmp_send_trap*, snmp_trap_dst_*): upstream SNMP code is not
 * thread-safe. Other tasks hand work to it through the message queue (snmp_transport_post).
 *
 * Also provides the transport hooks upstream expects from its transport file:
 * snmp_sendto() and snmp_get_local_ip_for_dst() (snmp_msg.h). */
#include "snmp_transport.h"

#include <stdatomic.h>
#include <string.h>

#include "esp_log.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "lwip/api.h"
#include "lwip/apps/snmp.h"
#include "lwip/def.h"
#include "lwip/ip_addr.h"
#include "lwip/prot/iana.h"
#include "snmp_lwip_port.h"
#include "snmp_msg.h"
#include "snmp_transport_util.h"

/* Static asserts tie the header's sizes to the project-wide lwIP SNMP options. */
_Static_assert(SNMP_COMMUNITY_SZ == SNMP_MAX_COMMUNITY_STR_LEN + 1, "SNMP_COMMUNITY_SZ mismatch");
_Static_assert(SNMP_AGENT_PORT == LWIP_IANA_PORT_SNMP, "SNMP port");
_Static_assert(SNMP_MSG_MAX <= UINT16_MAX, "msg length field");
_Static_assert(SNMP_TR_V1 == SNMP_VERSION_1 && SNMP_TR_V2C == SNMP_VERSION_2c && SNMP_TR_V3 == SNMP_VERSION_3,
               "snmp_transport_util.h version codes");
_Static_assert(LWIP_IANA_PORT_SNMP_TRAP == 162, "snmp_tr_dest_port");

static const char *TAG = "snmp_tr";

/* Non-empty placeholder used as both communities while a v3 datagram is processed (see header). */
static const char V3_COMMUNITY[] = "\x01usm";

typedef struct {
    uint16_t len;
    uint8_t data[SNMP_MSG_MAX];
} queued_msg_t;

typedef struct {
    char user[SNMP_COMMUNITY_SZ];
    snmp_user_access_t access;
    bool user_set; /* first snmp_ctx_set_user() of this datagram wins */
    uint8_t version;
    uint32_t peer_ip;
} req_ctx_t;

static snmp_transport_hooks_t s_hooks;
static TaskHandle_t s_task;
static TaskHandle_t s_stopper;
static struct netconn *s_conn;
static QueueHandle_t s_queue;
static atomic_bool s_enabled;
static atomic_bool s_stop_req;
static atomic_uint s_dropped;

/* Agent task only. lwIP keeps pointers to the community strings, so they live here. */
static snmp_access_cfg_t s_access;
static char s_inform_community[SNMP_COMMUNITY_SZ];
static req_ctx_t s_ctx;
static uint16_t s_trap_port;
static bool s_in_receive; /* true while snmp_receive() runs: datagrams sent are responses */

/* sysUpTime in centiseconds since boot (TimeTicks, wraps after ~497 days). Used by upstream
 * snmp_traps.c through MIB2_COPY_SYSUPTIME_TO (snmp_lwip_port.h, forced include) so traps carry
 * the same sysUpTime that snmp_gw's mib_system reports (same formula there). */
uint32_t snmp_lwip_sysuptime_cs(void) {
    return (uint32_t)(esp_timer_get_time() / 10000);
}

err_t snmp_sendto(void *handle, struct pbuf *p, const ip_addr_t *dst, u16_t port) {
    port = snmp_tr_dest_port(s_in_receive, port, s_trap_port); /* trap/inform to a non-standard port */
    struct netbuf buf;
    memset(&buf, 0, sizeof(buf));
    buf.p = p;
    return netconn_sendto((struct netconn *)handle, &buf, dst, port);
}

typedef struct {
    ip4_addr_t dst;
    esp_netif_ip_info_t info;
} route_query_t;

/* Runs in the TCP/IP task via esp_netif_find_if(). */
static bool netif_on_dst_subnet(esp_netif_t *netif, void *arg) {
    route_query_t *q = arg;
    esp_netif_ip_info_t info;
    if (!esp_netif_is_netif_up(netif) || esp_netif_get_ip_info(netif, &info) != ESP_OK || info.ip.addr == 0) {
        return false;
    }
    if (((info.ip.addr ^ q->dst.addr) & info.netmask.addr) != 0) {
        return false;
    }
    q->info = info;
    return true;
}

/* Source address for v1 trap agent-addr. ip_route_get_local_ip() would need the TCP/IP core
 * lock, so resolve through esp_netif: interface on the destination subnet, else default. */
u8_t snmp_get_local_ip_for_dst(void *handle, const ip_addr_t *dst, ip_addr_t *result) {
    LWIP_UNUSED_ARG(handle);
    if (dst == NULL || result == NULL || !IP_IS_V4(dst)) {
        return 0;
    }
    route_query_t q = {.dst = *ip_2_ip4(dst)};
    if (esp_netif_find_if(netif_on_dst_subnet, &q) == NULL) {
        esp_netif_t *def = esp_netif_get_default_netif();
        if (def == NULL || esp_netif_get_ip_info(def, &q.info) != ESP_OK || q.info.ip.addr == 0) {
            return 0;
        }
    }
    ip_addr_set_ip4_u32(result, q.info.ip.addr);
    return 1;
}

/* snmp_tr_peek() on the first SNMP_TR_PEEK_BYTES of a (possibly chained) pbuf. */
static int peek_header(struct pbuf *p, int *pdu_tag, char community[SNMP_COMMUNITY_SZ]) {
    uint8_t h[SNMP_TR_PEEK_BYTES];
    const u16_t n = pbuf_copy_partial(p, h, sizeof(h), 0);
    return snmp_tr_peek(h, n, pdu_tag, community);
}

static bool version_enabled(int v) {
    switch (v) {
    case SNMP_VERSION_1:
        return s_access.v1;
    case SNMP_VERSION_2c:
        return s_access.v2c;
    case SNMP_VERSION_3:
        return s_access.v3;
    default:
        return false;
    }
}

static uint32_t addr_host_order(const ip_addr_t *a) {
    return (a != NULL && IP_IS_V4(a)) ? lwip_ntohl(ip4_addr_get_u32(ip_2_ip4(a))) : 0;
}

static void inform_ack_cb(struct snmp_request *request, void *arg) {
    LWIP_UNUSED_ARG(arg);
    if (s_hooks.on_inform_ack != NULL) {
        s_hooks.on_inform_ack(request->request_id, addr_host_order(request->source_ip), s_hooks.arg);
    }
}

/* A manager's GetResponse to one of our v2c informs: admitted only for a peer with an outstanding
 * inform, parsed against that target's trap community with lwIP's v2c switch forced on. */
static void handle_inform_ack(struct netbuf *buf, uint32_t peer) {
    if (s_hooks.inform_peer == NULL || !s_hooks.inform_peer(peer, s_inform_community, s_hooks.arg)) {
        return;
    }
    s_inform_community[SNMP_COMMUNITY_SZ - 1] = '\0';
    memset(&s_ctx, 0, sizeof(s_ctx));
    s_ctx.version = SNMP_VERSION_2c;
    s_ctx.peer_ip = peer;
    const u8_t v2c_was = snmp_v2c_enabled();
    snmp_v2c_enable(1);
    snmp_set_community(s_inform_community);
    s_in_receive = true;
    snmp_receive(s_conn, buf->p, netbuf_fromaddr(buf), netbuf_fromport(buf));
    s_in_receive = false;
    snmp_v2c_enable(v2c_was);
}

static void handle_datagram(struct netbuf *buf) {
    const ip_addr_t *src = netbuf_fromaddr(buf);
    uint32_t peer = addr_host_order(src);
    int pdu_tag;
    char community[SNMP_COMMUNITY_SZ];
    int version = peek_header(buf->p, &pdu_tag, community);
    if (pdu_tag == SNMP_TR_PDU_GET_RESP) {
        if (version == SNMP_VERSION_2c) {
            handle_inform_ack(buf, peer);
        }
        return; /* we are an agent: no other GetResponse is meaningful */
    }
    if (!atomic_load(&s_enabled)) {
        return;
    }
    uint32_t local = 0;
#if LWIP_NETBUF_RECVINFO
    if (buf->flags & NETBUF_FLAG_DESTADDR) {
        local = addr_host_order(netbuf_destaddr(buf));
    }
#endif
    if (s_hooks.accept != NULL && !s_hooks.accept(peer, local, s_hooks.arg)) {
        return;
    }
    if (!version_enabled(version)) {
        return;
    }

    memset(&s_ctx, 0, sizeof(s_ctx));
    s_ctx.version = (uint8_t)version;
    s_ctx.peer_ip = peer;
    switch (snmp_tr_pick_communities(version, community, s_access.rw)) {
    case SNMP_TR_COMM_V3:
        snmp_set_community(V3_COMMUNITY);
        snmp_set_community_write(V3_COMMUNITY);
        break;
    case SNMP_TR_COMM_RW:
        /* The read-write community also grants read access (lwIP compares GETs with the read
         * community only): treat it as the read community for this datagram. */
        snmp_set_community(s_access.rw);
        snmp_set_community_write(s_access.rw);
        break;
    case SNMP_TR_COMM_RO:
    default:
        snmp_set_community(s_access.ro);
        snmp_set_community_write(s_access.rw);
        break;
    }
    const u32_t auth_fails = snmp_stats.inbadcommunitynames + snmp_stats.wrongdigests;
    s_in_receive = true;
    snmp_receive(s_conn, buf->p, src, netbuf_fromport(buf));
    s_in_receive = false;
    if (snmp_stats.inbadcommunitynames + snmp_stats.wrongdigests != auth_fails &&
        s_hooks.on_auth_fail != NULL) {
        s_hooks.on_auth_fail(peer, s_hooks.arg);
    }
}

static void drain_queue(void) {
    queued_msg_t m;
    for (int i = 0; i < SNMP_MSG_QUEUE_LEN && xQueueReceive(s_queue, &m, 0) == pdTRUE; i++) {
        if (s_hooks.on_msg != NULL) {
            s_hooks.on_msg(m.data, m.len, s_hooks.arg);
        }
    }
}

static void agent_task(void *arg) {
    LWIP_UNUSED_ARG(arg);
    snmp_set_auth_traps_enabled(0); /* fanned out by snmp_gw via on_auth_fail (see header) */
    snmp_set_inform_callback(inform_ack_cb, NULL);
    if (s_hooks.on_start != NULL) {
        s_hooks.on_start(s_hooks.arg);
    }
    while (!atomic_load(&s_stop_req)) {
        struct netbuf *buf = NULL;
        err_t err = netconn_recv(s_conn, &buf);
        if (err == ERR_OK && buf != NULL) {
            handle_datagram(buf);
        } else if (err != ERR_TIMEOUT) {
            ESP_LOGW(TAG, "netconn_recv: %d", err);
            vTaskDelay(pdMS_TO_TICKS(10)); /* avoid a hot loop on persistent errors */
        }
        if (buf != NULL) {
            netbuf_delete(buf);
        }
        drain_queue();
        if (s_hooks.on_idle != NULL) {
            s_hooks.on_idle(s_hooks.arg);
        }
    }

    snmp_traps_handle = NULL;
    netconn_delete(s_conn);
    s_conn = NULL;
    TaskHandle_t stopper = s_stopper;
    s_task = NULL;
    if (stopper != NULL) {
        xTaskNotifyGive(stopper);
    }
    vTaskDelete(NULL);
}

esp_err_t snmp_transport_start(const snmp_transport_hooks_t *hooks) {
    if (s_task != NULL) {
        return ESP_ERR_INVALID_STATE;
    }
    if (hooks != NULL) {
        s_hooks = *hooks;
    } else {
        memset(&s_hooks, 0, sizeof(s_hooks));
    }
    memset(&s_access, 0, sizeof(s_access));
    atomic_store(&s_stop_req, false);
    s_stopper = NULL;

    if (s_queue == NULL) {
        s_queue = xQueueCreate(SNMP_MSG_QUEUE_LEN, sizeof(queued_msg_t));
        if (s_queue == NULL) {
            return ESP_ERR_NO_MEM;
        }
    }
    s_conn = netconn_new(NETCONN_UDP);
    if (s_conn == NULL) {
        return ESP_ERR_NO_MEM;
    }
    err_t err = netconn_bind(s_conn, IP4_ADDR_ANY, SNMP_AGENT_PORT);
    if (err != ERR_OK) {
        ESP_LOGE(TAG, "bind udp/%d: %d", SNMP_AGENT_PORT, err);
        netconn_delete(s_conn);
        s_conn = NULL;
        return ESP_FAIL;
    }
    netconn_set_recvtimeout(s_conn, SNMP_RECV_TIMEOUT_MS);
    snmp_traps_handle = s_conn;

    if (xTaskCreatePinnedToCore(agent_task, SNMP_AGENT_TASK_NAME, SNMP_AGENT_TASK_STACK, NULL,
                                SNMP_AGENT_TASK_PRIO, &s_task, SNMP_AGENT_TASK_CORE) != pdPASS) {
        snmp_traps_handle = NULL;
        netconn_delete(s_conn);
        s_conn = NULL;
        s_task = NULL;
        return ESP_ERR_NO_MEM;
    }
    ESP_LOGI(TAG, "agent listening on udp/%d", SNMP_AGENT_PORT);
    return ESP_OK;
}

esp_err_t snmp_transport_stop(uint32_t timeout_ms) {
    if (s_task == NULL) {
        return ESP_ERR_INVALID_STATE;
    }
    if (snmp_transport_in_agent_thread()) {
        return ESP_ERR_INVALID_STATE;
    }
    s_stopper = xTaskGetCurrentTaskHandle();
    atomic_store(&s_stop_req, true);
    /* The agent notices the request within one receive timeout. */
    if (ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(timeout_ms)) == 0) {
        return ESP_ERR_TIMEOUT;
    }
    return ESP_OK;
}

void snmp_transport_set_enabled(bool enabled) {
    atomic_store(&s_enabled, enabled);
}

void snmp_transport_set_access(const snmp_access_cfg_t *cfg) {
    if (cfg == NULL) {
        memset(&s_access, 0, sizeof(s_access));
    } else {
        s_access = *cfg;
        s_access.ro[SNMP_COMMUNITY_SZ - 1] = '\0';
        s_access.rw[SNMP_COMMUNITY_SZ - 1] = '\0';
    }
    /* Mirror the enables into lwIP so its own counters/checks agree with the transport filter. */
    snmp_v1_enable(s_access.v1);
    snmp_v2c_enable(s_access.v2c);
    snmp_v3_enable(s_access.v3);
}

void snmp_transport_set_trap_port(uint16_t port) {
    s_trap_port = (port == LWIP_IANA_PORT_SNMP_TRAP) ? 0 : port;
}

esp_err_t snmp_transport_post(const void *msg, size_t len, uint32_t timeout_ms) {
    if (msg == NULL || len == 0 || len > SNMP_MSG_MAX) {
        return ESP_ERR_INVALID_ARG;
    }
    if (s_queue == NULL) {
        return ESP_ERR_INVALID_STATE;
    }
    queued_msg_t m;
    m.len = (uint16_t)len;
    memcpy(m.data, msg, len);
    if (xQueueSend(s_queue, &m, pdMS_TO_TICKS(timeout_ms)) != pdTRUE) {
        atomic_fetch_add(&s_dropped, 1);
        return ESP_ERR_TIMEOUT;
    }
    return ESP_OK;
}

uint32_t snmp_transport_dropped(void) {
    return atomic_load(&s_dropped);
}

bool snmp_transport_in_agent_thread(void) {
    return s_task != NULL && xTaskGetCurrentTaskHandle() == s_task;
}

void snmp_ctx_set_user(const char *user, snmp_user_access_t access) {
    if (s_ctx.user_set) {
        return; /* later lookups are usmUserTable rows, not the requesting principal */
    }
    s_ctx.user_set = true;
    size_t n = user ? strnlen(user, sizeof(s_ctx.user) - 1) : 0;
    memcpy(s_ctx.user, user ? user : "", n);
    s_ctx.user[n] = '\0';
    s_ctx.access = access;
}

bool snmp_ctx_can_write(void) {
    return s_ctx.version != SNMP_VERSION_3 || s_ctx.access == SNMP_ACCESS_RW;
}

const char *snmp_ctx_user(void) {
    return s_ctx.user;
}

uint8_t snmp_ctx_version(void) {
    return s_ctx.version;
}

uint32_t snmp_ctx_peer_ip(void) {
    return s_ctx.peer_ip;
}

/*
 * ws_hub.h - WebSocket endpoint /ws and broadcast hub (DESIGN.md §7, docs/API.md §WebSocket).
 *
 * Handshake: pre-handshake callback requires, in this order, an allowed Host (net_host_allowed(),
 * else 421), a valid session cookie (no touch, else 401), a session WITHOUT must_change (else 403:
 * nothing is streamed before the factory password is changed) and, when Origin is present, Origin
 * authority == Host (else 403); otherwise the upgrade is refused. Existing sockets of a session that
 * gets revoked (incl. an admin setting must_change, auth.h) receive bye "revoked". At most
 * GW_MAX_WS_CLIENTS: a further handshake is refused with 503 (existing clients are never evicted).
 * Right after the handshake the hub sends "hello". Clients subscribe with
 * {"t":"sub","topics":[...]}; nothing but hello/pong/bye is sent before that.
 *
 * Frames are built ONCE per event by gw_evt handlers registered in ws_hub_init() (SNAPSHOT, ALARM,
 * WRITE_RESULT, COMM, SYS_TICK, SESSION, REBOOT) and broadcast as ref-counted PSRAM buffers via
 * httpd_queue_work() -> httpd_ws_send_frame_async() to every WS client subscribed to the topic
 * whose session is still valid (auth_session_check). A failed or timed-out send closes that client.
 *
 * Threading: broadcast/send/close functions are non-blocking and callable from any task (normally
 * gw_evt); actual socket I/O happens in the httpd task.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "auth/auth.h"
#include "esp_err.h"
#include "esp_http_server.h"

#ifdef __cplusplus
extern "C" {
#endif

#define WS_PATH "/ws"
#define WS_PROTO_VERSION 1
#define WS_RX_MAX 256     /* client frames larger than this close the connection (1009) */
#define WS_FRAME_MAX 4096 /* largest server frame */
#define WS_FRAME_POOL 8   /* in-flight broadcast buffers */
#define WS_FULL_SNAP_S 30 /* full snapshot period */
#define WS_COMM_PERIOD_S 5
#define WS_SYS_PERIOD_S 10

typedef enum {
    WS_T_SNAP = 1u << 0,
    WS_T_ALARM = 1u << 1,
    WS_T_COMM = 1u << 2,
    WS_T_WRITE = 1u << 3,
    WS_T_SYS = 1u << 4,
} ws_topic_t;
#define WS_TOPIC_ALL 0x1Fu

/** bye reasons (wire strings) */
#define WS_BYE_SESSION_EXPIRED "session_expired"
#define WS_BYE_LOGOUT "logout"
#define WS_BYE_REVOKED "revoked"
#define WS_BYE_REBOOT "reboot"

/** Register the /ws URI (with ws_pre_handshake_cb) on server and the gw_evt frame builders. */
esp_err_t ws_hub_init(httpd_handle_t server);

/** httpd close_fn hook: forget the socket if it was a WS client. httpd task only. */
void ws_hub_on_close(int sockfd);

/**
 * Broadcast a text frame to clients subscribed to any topic in `topics`. The JSON is copied into a
 * pool buffer; ESP_ERR_NO_MEM when the pool is exhausted (frame dropped, counted).
 */
esp_err_t ws_hub_broadcast(uint32_t topics, const char *json, size_t len);

/** Send a text frame to one client (hello/pong/bye). */
esp_err_t ws_hub_send_to(int sockfd, const char *json, size_t len);

/** Send {"t":"bye","reason":reason} to every client of session sid, then close them. */
void ws_hub_close_session(auth_sid_t sid, const char *reason);

/** Send bye to all clients and close them (reboot). */
void ws_hub_close_all(const char *reason);

/** Union of topics subscribed by current clients (skip building unwanted frames). */
uint32_t ws_hub_topics(void);

/** Test-and-clear: some client subscribed to snap since the last full frame for dev was sent. */
bool ws_hub_take_full_request(uint8_t dev);

/** Connected WS clients. */
size_t ws_hub_client_count(void);

#ifdef __cplusplus
}
#endif

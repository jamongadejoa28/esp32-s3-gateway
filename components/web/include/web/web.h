/*
 * web.h - HTTP server lifecycle.
 *
 * web_start() creates the httpd instance (port 80; max_uri_handlers 8, max_open_sockets 12,
 * max_resp_headers 12, lru_purge_enable, keep-alive, send_wait_timeout 3 s, stack 8192, core 0,
 * open_fn = net_ip_allowed_fd() allowlist, close_fn = ws_hub_on_close()), registers the wildcard
 * handlers, the route tables of every api_*.c (web_router_register) and ws_hub_init(), and starts
 * the HTTPD heartbeat: a 2 s esp_timer queues a no-op httpd_queue_work() item that calls
 * gw_hb_beat(GW_HB_HTTPD) (gw_core/gw_health.h), proving the httpd task is alive.
 * Reboots need no call into web: ws_hub's GW_EVT_REBOOT handler sends bye "reboot".
 * Static UI: the generated asset table of web/web_assets.h.
 * Call after auth_init() (init order step 11). Not thread-safe against itself: call from app_main
 * or the console only.
 */
#pragma once

#include <stdbool.h>

#include "gw_core/gw_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define WEB_HTTP_PORT 80

/** Start the server. ESP_ERR_INVALID_STATE if already running. */
esp_err_t web_start(void);

/** Close all WS clients (bye "reboot" if `rebooting`) and stop the server (console/tests only). */
esp_err_t web_stop(bool rebooting);

/** True while the server runs. */
bool web_running(void);

/** httpd handle as void* (NULL when stopped), for components that must queue work on it. */
void *web_server_handle(void);

#ifdef __cplusplus
}
#endif

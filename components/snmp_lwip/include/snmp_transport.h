/*
 * snmp_transport.h - single-threaded SNMP agent transport replacing lwIP snmp_netconn.c
 * (DESIGN.md §0, §10). Device-only header: includes esp_err.h directly and no gw_core header
 * (snmp_lwip publicly REQUIRES only lwip; PRIV_REQUIRES gw_core for the RFC 3414 key localization
 * that snmpv3_psa.c delegates to gw_snmp_key_localize()).
 *
 * One task "snmp_agent" (prio 4, core 0, stack 6144) owns a UDP/161 netconn bound to
 * IP4_ADDR_ANY (snmp_traps_handle = conn). EVERY lwIP SNMP API call (snmp_receive, snmp_set_*,
 * snmp_send_trap*, snmp_send_inform*, snmp_trap_dst_*) happens in this task only. Loop:
 *   netconn_recv (SNMP_RECV_TIMEOUT_MS) ->
 *     inform ack: a v1/v2c-framed GetResponse PDU (tag 0xA2, i.e. the manager's acknowledgement of
 *               an inform we sent) for which hooks.inform_peer() returns true bypasses the enable,
 *               accept() and version filters; it is parsed with snmp_community = the community
 *               inform_peer() returned (lwIP compares a GetResponse with the READ community) and
 *               with lwIP's v2c enable forced on for that one datagram; lwIP's inform callback is
 *               registered by the transport and forwarded to hooks.on_inform_ack(request_id, peer).
 *               Any other GetResponse is dropped.
 *     datagram: drop if !enabled, if hooks.accept() rejects, or if its SNMP version (peeked from
 *               the BER header) is disabled -> per-request ctx reset -> apply the per-version
 *               community mapping (below) -> snmp_receive(); if lwIP counted an authentication
 *               failure (snmp_stats.inbadcommunitynames or .wrongdigests grew) hooks.on_auth_fail(peer)
 *               is called.
 *     always:   drain the message queue into hooks.on_msg() (traps etc.), then hooks.on_idle().
 *
 * Authentication-failure traps: lwIP's own snmp_authfail_trap() is kept disabled
 * (snmp_set_auth_traps_enabled(0) at start; snmp_gw must never enable it) because it would go to
 * whatever destination slot 0 last pointed at. snmp_gw fans authenticationFailure out to every
 * enabled target from on_auth_fail() when cfg_snmp_t.auth_traps is set.
 *
 * Trap destination port: lwIP always sends traps/informs to port 162; snmp_sendto() replaces 162
 * by the port set with snmp_transport_set_trap_port() for datagrams sent OUTSIDE snmp_receive()
 * (i.e. traps/informs; responses inside snmp_receive keep the requester's port).
 *
 * Community mapping (works around lwIP snmp_msg.c, verified in IDF 6.1): for SNMPv3 lwIP copies
 * the READ community into the request and then applies the v1/v2c write-community check to SETs,
 * and rejects the request outright when the read community is empty. Therefore, per datagram:
 *   v1/v2c: snmp_set_community(ro), snmp_set_community_write(rw)    (rw "" => SET -> notWritable);
 *           a request that carries the (non-empty) RW community also gets it as the READ
 *           community for that datagram, so the RW community reads too (net-snmp rwcommunity)
 *   v3:     both set to the same internal non-empty placeholder, so lwIP's check passes; RO/RW for
 *           v3 is enforced by snmp_ctx_can_write() in every writable node's set_test.
 * Communities are configured with snmp_transport_set_access() (agent task only).
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SNMP_AGENT_TASK_NAME "snmp_agent"
#define SNMP_AGENT_TASK_PRIO 4
#define SNMP_AGENT_TASK_CORE 0
#define SNMP_AGENT_TASK_STACK 6144
#define SNMP_AGENT_PORT 161
#define SNMP_RECV_TIMEOUT_MS 100
#define SNMP_MSG_MAX 96 /* bytes per queued message */
#define SNMP_MSG_QUEUE_LEN 16
#define SNMP_COMMUNITY_SZ 33 /* SNMP_MAX_COMMUNITY_STR_LEN (32, project define) + NUL */

typedef enum {
    SNMP_ACCESS_NONE = 0,
    SNMP_ACCESS_RO = 1,
    SNMP_ACCESS_RW = 2
} snmp_user_access_t; /* not snmp_access_t: lwIP snmp_core.h owns that name */

/** Hooks; every callback runs in the agent task. Any may be NULL. */
typedef struct {
    /** Once, before the first receive: install MIBs (snmp_registry_start), engine id, access. */
    void (*on_start)(void *arg);
    /** After every receive or timeout (<= SNMP_RECV_TIMEOUT_MS cadence): config apply, inform retries. */
    void (*on_idle)(void *arg);
    /** One queued message posted with snmp_transport_post(). */
    void (*on_msg)(const void *msg, size_t len, void *arg);
    /** Per datagram: allowlist check (peer/local IPv4, host order). Return false to drop. */
    bool (*accept)(uint32_t peer_ip, uint32_t local_ip, void *arg);
    /**
     * Inform-ack admission: peer_ip has an outstanding v2c inform? Then copy that trap target's
     * community into community (NUL-terminated, < SNMP_COMMUNITY_SZ) and return true. NULL hook =
     * no informs (every GetResponse is dropped). Keyed by IP only (known limitation, DECISIONS.md
     * E): with two targets on the same IP but different ports/communities the second target's
     * ack is parsed with the first one's community and dropped (the inform is retried, then
     * counted as failed).
     */
    bool (*inform_peer)(uint32_t peer_ip, char community[SNMP_COMMUNITY_SZ], void *arg);
    /** An inform was acknowledged (error-status noError): request_id as returned by snmp_send_inform*. */
    void (*on_inform_ack)(int32_t request_id, uint32_t peer_ip, void *arg);
    /** A request failed authentication (wrong v1/v2c community or wrong SNMPv3 digest). */
    void (*on_auth_fail)(uint32_t peer_ip, void *arg);
    void *arg;
} snmp_transport_hooks_t;

/** Version enables and v1/v2c communities (copied). */
typedef struct {
    bool v1, v2c, v3;
    char ro[SNMP_COMMUNITY_SZ]; /* "" => v1/v2c GET rejected as bad community */
    char rw[SNMP_COMMUNITY_SZ]; /* "" => v1/v2c SET answered notWritable */
} snmp_access_cfg_t;

/** Create the agent task (always, even when SNMP is disabled). ESP_ERR_INVALID_STATE if running. */
esp_err_t snmp_transport_start(const snmp_transport_hooks_t *hooks);

/** Stop the task and close the socket (tests / shutdown). Any task except the agent. */
esp_err_t snmp_transport_stop(uint32_t timeout_ms);

/** Master enable: when false every datagram is dropped (queue is still drained). Any task. */
void snmp_transport_set_enabled(bool enabled);

/** [agent task] Set version enables and communities used by the per-datagram mapping. */
void snmp_transport_set_access(const snmp_access_cfg_t *cfg);

/**
 * [agent task] Destination UDP port for the following snmp_send_trap*()/snmp_send_inform*() calls
 * (snmp_gw sets it per target together with snmp_trap_dst_ip_set(0, ...)). 0 or 162 = standard.
 */
void snmp_transport_set_trap_port(uint16_t port);

/** Queue a message (copied, <= SNMP_MSG_MAX) for on_msg(). Any task, not ISR. ESP_ERR_TIMEOUT if full. */
esp_err_t snmp_transport_post(const void *msg, size_t len, uint32_t timeout_ms);

/** Messages dropped because the queue was full. */
uint32_t snmp_transport_dropped(void);

/** True when called from the agent task. */
bool snmp_transport_in_agent_thread(void);

/* ---- Per-request context (agent task only; reset before every snmp_receive) ---- */

/**
 * Record the resolved SNMPv3 user of the current request. usm.c calls it from snmpv3_get_user()
 * for a known, enabled user. Only the FIRST call per datagram is kept (that is lwIP's lookup of
 * msgUserName, snmp_msg.c, before authentication); later calls - lwIP also calls snmpv3_get_user()
 * for every usmUserTable row it reads - are ignored, so the context always names the authenticated
 * principal.
 */
void snmp_ctx_set_user(const char *user, snmp_user_access_t access);

/** True for v1/v2c requests (lwIP already enforced the write community) or a v3 RW user. */
bool snmp_ctx_can_write(void);

/** Resolved v3 user name, or "" for community requests. */
const char *snmp_ctx_user(void);

/** Version of the current request (0 = v1, 1 = v2c, 3 = v3). */
uint8_t snmp_ctx_version(void);

/** Peer IPv4 (host order) of the current request. */
uint32_t snmp_ctx_peer_ip(void);

#ifdef __cplusplus
}
#endif

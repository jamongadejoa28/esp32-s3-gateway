/* snmp_transport_util.h - pure per-datagram decisions of snmp_transport.c (private to snmp_lwip).
 *
 * Header-only and free of IDF/lwIP/FreeRTOS headers, so the host tests compile the exact code the
 * transport runs (tests/snmp_host/transport_util_driver.c, tests/test_snmp_transport_pure.py). */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "snmp_transport.h"

/** BER tag of a GetResponse PDU (context class, constructed, 2): an inform acknowledgement. */
#define SNMP_TR_PDU_GET_RESP 0xA2
/** Bytes of a datagram that snmp_tr_peek() looks at (header + a maximal short-form community). */
#define SNMP_TR_PEEK_BYTES 64

#define SNMP_TR_V1 0  /* SNMP_VERSION_1 */
#define SNMP_TR_V2C 1 /* SNMP_VERSION_2c */
#define SNMP_TR_V3 3  /* SNMP_VERSION_3 */

/**
 * Peek the BER header h[0..n): SEQUENCE { INTEGER version, OCTET STRING community, PDU ... }.
 * Returns the version (-1 if unparsable). For v1/v2c framing with a short-form community length
 * (always the case for a community lwIP accepts) *pdu_tag receives the PDU tag and community[] the
 * NUL-terminated community ("" when it is longer than SNMP_COMMUNITY_SZ - 1); otherwise *pdu_tag is
 * -1 and community is "". Never reads beyond h[n - 1].
 */
static inline int snmp_tr_peek(const uint8_t *h, size_t n, int *pdu_tag, char community[SNMP_COMMUNITY_SZ]) {
    *pdu_tag = -1;
    community[0] = '\0';
    if (h == NULL || n < 5 || h[0] != 0x30) {
        return -1;
    }
    size_t i = 2;
    if (h[1] & 0x80) {
        const size_t k = h[1] & 0x7Fu;
        if (k == 0 || k > 2) {
            return -1;
        }
        i += k;
    }
    if (i + 3 > n || h[i] != 0x02 || h[i + 1] != 0x01) {
        return -1;
    }
    const int version = h[i + 2];
    i += 3;
    if (i + 2 <= n && h[i] == 0x04 && h[i + 1] < 0x80 && i + 2 + h[i + 1] < n) {
        const size_t clen = h[i + 1];
        *pdu_tag = h[i + 2 + clen];
        if (clen <= SNMP_COMMUNITY_SZ - 1) {
            memcpy(community, &h[i + 2], clen);
            community[clen] = '\0';
        }
    }
    return version;
}

/** Communities lwIP gets for one datagram (snmp_transport.h "Community mapping"). */
typedef enum {
    SNMP_TR_COMM_V3 = 0, /* both = the internal v3 placeholder (RO/RW enforced by snmp_ctx_can_write) */
    SNMP_TR_COMM_RW = 1, /* read = write = the RW community: the RW community also reads */
    SNMP_TR_COMM_RO = 2, /* read = RO community, write = RW community (lwIP decides per PDU type) */
} snmp_tr_comm_t;

/**
 * Community mapping for a datagram of `version` carrying `community`, given the configured RW
 * community `rw` ("" = none). An empty RW community never matches (an empty request community would
 * otherwise gain write access).
 */
static inline snmp_tr_comm_t snmp_tr_pick_communities(int version, const char *community, const char *rw) {
    if (version == SNMP_TR_V3) {
        return SNMP_TR_COMM_V3;
    }
    if (rw != NULL && rw[0] != '\0' && community != NULL && strcmp(community, rw) == 0) {
        return SNMP_TR_COMM_RW;
    }
    return SNMP_TR_COMM_RO;
}

/** Destination port for an outgoing datagram: traps/informs (sent outside snmp_receive) to the
 * standard trap port go to the configured target port instead (0 = standard). */
static inline uint16_t snmp_tr_dest_port(bool in_receive, uint16_t port, uint16_t trap_port) {
    return (!in_receive && port == 162 && trap_port != 0) ? trap_port : port;
}

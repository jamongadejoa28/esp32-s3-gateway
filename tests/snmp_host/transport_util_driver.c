/* Host wrappers around components/snmp_lwip/snmp_transport_util.h (header-only, the code
 * snmp_transport.c runs) for tests/test_snmp_transport_pure.py (ctypes). */
#include "snmp_transport_util.h"

int tr_peek(const uint8_t *h, size_t n, int *pdu_tag, char *community) {
    return snmp_tr_peek(h, n, pdu_tag, community);
}

int tr_pick(int version, const char *community, const char *rw) {
    return (int)snmp_tr_pick_communities(version, community, rw);
}

int tr_dest_port(int in_receive, int port, int trap_port) {
    return snmp_tr_dest_port(in_receive != 0, (uint16_t)port, (uint16_t)trap_port);
}

int tr_community_sz(void) {
    return SNMP_COMMUNITY_SZ;
}

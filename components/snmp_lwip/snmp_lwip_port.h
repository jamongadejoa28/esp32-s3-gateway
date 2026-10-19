/* snmp_lwip_port.h - project overrides for the upstream lwIP SNMP sources (private to snmp_lwip).
 *
 * Force-included into upstream snmp_traps.c (CMakeLists.txt: -include). lwIP only defines
 * MIB2_COPY_SYSUPTIME_TO when MIB2_STATS is enabled (lwip/snmp.h); otherwise the macro expands to
 * nothing and every trap would carry sysUpTime 0 (v1 time-stamp and the v2c sysUpTime.0 varbind).
 * IDF builds lwIP with MIB2_STATS=0, so the agent supplies its own uptime source here. */
#pragma once

#include <stdint.h>

/** sysUpTime: centiseconds since boot (implemented in snmp_transport.c). */
uint32_t snmp_lwip_sysuptime_cs(void);

#define MIB2_COPY_SYSUPTIME_TO(ptrToVal) (*(ptrToVal) = snmp_lwip_sysuptime_cs())

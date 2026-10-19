/* Host build of the lwIP SNMP agent for tests/test_snmp_agent_host.py (NO_SYS, libc malloc). The SNMP
 * options mirror the project-wide set in the top-level CMakeLists.txt, except the receive API (the
 * host harness feeds snmp_receive() directly, like snmp_transport.c does on the device). */
#pragma once
#include <stdlib.h>

#define NO_SYS 1
#define SYS_LIGHTWEIGHT_PROT 0
#define LWIP_NETCONN 0
#define LWIP_SOCKET 0
#define LWIP_IPV4 1
#define LWIP_IPV6 0
#define LWIP_UDP 1
#define LWIP_TCP 0
#define LWIP_RAW 0
#define LWIP_DHCP 0
#define LWIP_DNS 0
#define LWIP_ARP 0
#define LWIP_ICMP 0
#define LWIP_IGMP 0
#define LWIP_STATS 0
#define MEM_LIBC_MALLOC 1
#define MEMP_MEM_MALLOC 1
#define MEM_ALIGNMENT 8
#define LWIP_RAND() ((u32_t)rand())
#define LWIP_DONT_PROVIDE_BYTEORDER_FUNCTIONS 1 /* the harness uses the libc ones (arpa/inet.h) */

#define LWIP_SNMP 1
#define SNMP_USE_RAW 1
#define SNMP_USE_NETCONN 0
#define LWIP_SNMP_V3 1
#define LWIP_SNMP_V3_CRYPTO 1
#define LWIP_SNMP_V3_MBEDTLS 0
#define LWIP_SNMP_CONFIGURE_VERSIONS 1
#define SNMP_LWIP_MIB2 0
#define SNMP_TRAP_DESTINATIONS 1
#define SNMP_MAX_COMMUNITY_STR_LEN 32
#define SNMP_MAX_OBJ_ID_LEN 50
#define SNMP_LWIP_GETBULK_MAX_REPETITIONS 16

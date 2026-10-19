/* Host (gcc, Linux) port definitions for the lwIP SNMP test harness. */
#pragma once
#include <stdio.h>
#include <stdlib.h>

#define LWIP_PLATFORM_DIAG(x) do { printf x; } while (0)
#define LWIP_PLATFORM_ASSERT(x) do { fprintf(stderr, "lwIP assert: %s (%s:%d)\n", x, __FILE__, __LINE__); abort(); } while (0)
#ifndef BYTE_ORDER
#define BYTE_ORDER LITTLE_ENDIAN
#endif
#define LWIP_ERR_T int

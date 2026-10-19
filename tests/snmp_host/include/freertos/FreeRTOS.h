/* Host shim of the FreeRTOS subset used by components/snmp_gw/traps.c (tests/snmp_host/trap_harness.c).
 * Single-threaded: semaphores are counters that never block, critical sections are no-ops. */
#pragma once
#include <stdbool.h>
#include <stdint.h>

#define pdTRUE 1
#define pdFALSE 0
#define pdPASS pdTRUE
#define pdMS_TO_TICKS(ms) ((uint32_t)(ms))
#define portMAX_DELAY UINT32_MAX

typedef int BaseType_t;
typedef uint32_t TickType_t;
typedef int portMUX_TYPE;
#define portMUX_INITIALIZER_UNLOCKED 0
#define taskENTER_CRITICAL(mux) ((void)(mux))
#define taskEXIT_CRITICAL(mux) ((void)(mux))

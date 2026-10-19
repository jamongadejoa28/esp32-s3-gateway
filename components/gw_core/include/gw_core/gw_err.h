/*
 * gw_err.h - esp_err_t for pure-logic headers.
 *
 * Inside an ESP-IDF build (ESP_PLATFORM defined by the IDF build system) this simply includes
 * esp_err.h. On the host (unit tests compiled with plain gcc) it provides an ABI-identical
 * typedef and the subset of codes used by this project, with the exact values of IDF 6.1
 * esp_common/include/esp_err.h. Pure headers include this instead of esp_err.h directly.
 */
#pragma once

#if defined(ESP_PLATFORM)
#include "esp_err.h"
#else
typedef int esp_err_t;
#define ESP_OK 0
#define ESP_FAIL -1
#define ESP_ERR_NO_MEM 0x101
#define ESP_ERR_INVALID_ARG 0x102
#define ESP_ERR_INVALID_STATE 0x103
#define ESP_ERR_INVALID_SIZE 0x104
#define ESP_ERR_NOT_FOUND 0x105
#define ESP_ERR_NOT_SUPPORTED 0x106
#define ESP_ERR_TIMEOUT 0x107
#define ESP_ERR_INVALID_RESPONSE 0x108
#define ESP_ERR_INVALID_CRC 0x109
#define ESP_ERR_INVALID_VERSION 0x10A
#define ESP_ERR_INVALID_MAC 0x10B
#define ESP_ERR_NOT_FINISHED 0x10C
#define ESP_ERR_NOT_ALLOWED 0x10D
#endif

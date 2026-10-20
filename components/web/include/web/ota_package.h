/* GWOTA1: 80-byte little-endian header, application, then a complete LittleFS image. */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define WEB_OTA_HEADER_SIZE 80u
#define WEB_OTA_APP_LIMIT 0x280000u
#define WEB_OTA_FS_SIZE 0x80000u

static inline uint32_t web_ota_u32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline bool web_ota_header_valid(const uint8_t *h, size_t total) {
    if (!h || total < WEB_OTA_HEADER_SIZE || memcmp(h, "GWOTA1\r\n", 8) != 0)
        return false;
    const uint32_t app = web_ota_u32(h + 8), web = web_ota_u32(h + 12);
    return app >= 288u && app <= WEB_OTA_APP_LIMIT && web == WEB_OTA_FS_SIZE &&
           total == WEB_OTA_HEADER_SIZE + (size_t)app + web;
}

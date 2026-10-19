/* Host shim of esp_log.h for the lwIP SNMP harness: logs to stderr. */
#pragma once
#include <stdio.h>

#define ESP_LOG_HOST_(lvl, tag, fmt, ...) fprintf(stderr, lvl " (%s) " fmt "\n", tag, ##__VA_ARGS__)
#define ESP_LOGE(tag, fmt, ...) ESP_LOG_HOST_("E", tag, fmt, ##__VA_ARGS__)
#define ESP_LOGW(tag, fmt, ...) ESP_LOG_HOST_("W", tag, fmt, ##__VA_ARGS__)
#define ESP_LOGI(tag, fmt, ...) ESP_LOG_HOST_("I", tag, fmt, ##__VA_ARGS__)
#define ESP_LOGD(tag, fmt, ...) ESP_LOG_HOST_("D", tag, fmt, ##__VA_ARGS__)

const char *esp_err_to_name(int code);

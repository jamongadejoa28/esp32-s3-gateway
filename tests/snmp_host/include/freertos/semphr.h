/* Host shim (see FreeRTOS.h): a semaphore is a counter; Take never blocks (a timeout elapses at once). */
#pragma once
#include "freertos/FreeRTOS.h"

typedef struct {
    int count;
    int max;
} StaticSemaphore_t;
typedef StaticSemaphore_t *SemaphoreHandle_t;

static inline SemaphoreHandle_t xSemaphoreCreateMutexStatic(StaticSemaphore_t *b) {
    b->count = 1;
    b->max = 1;
    return b;
}
static inline SemaphoreHandle_t xSemaphoreCreateBinaryStatic(StaticSemaphore_t *b) {
    b->count = 0;
    b->max = 1;
    return b;
}
static inline BaseType_t xSemaphoreTake(SemaphoreHandle_t s, TickType_t ticks) {
    (void)ticks;
    if (s->count > 0) {
        s->count--;
        return pdTRUE;
    }
    return pdFALSE;
}
static inline BaseType_t xSemaphoreGive(SemaphoreHandle_t s) {
    if (s->count >= s->max) {
        return pdFALSE;
    }
    s->count++;
    return pdTRUE;
}

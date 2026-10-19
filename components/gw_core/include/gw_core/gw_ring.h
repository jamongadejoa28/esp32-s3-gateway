/*
 * gw_ring.h - overwrite-oldest ring of fixed-size records in caller-provided memory (pure C).
 *
 * Header-only (trivial index arithmetic). Used by history (PSRAM rings), eventlog RAM tail,
 * ws/snmp scratch queues. NOT thread-safe: the owner serialises access (mutex or single task).
 * Indexing: 0 = oldest record currently held, count-1 = newest.
 */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef struct {
    uint8_t *base;     /* cap * rec_size bytes, owned by the caller */
    uint32_t rec_size; /* bytes per record (> 0) */
    uint32_t cap;      /* records (> 0) */
    uint32_t head;     /* slot index of the next write */
    uint32_t count;    /* records held, <= cap */
} gw_ring_t;

/** Bind the ring to `mem` (cap * rec_size bytes) and empty it. */
static inline void gw_ring_init(gw_ring_t *r, void *mem, uint32_t rec_size, uint32_t cap) {
    r->base = (uint8_t *)mem;
    r->rec_size = rec_size;
    r->cap = cap;
    r->head = 0;
    r->count = 0;
}

/** Forget all records (memory untouched). */
static inline void gw_ring_clear(gw_ring_t *r) {
    r->head = 0;
    r->count = 0;
}

/** Reserve the next slot (overwriting the oldest when full) and return it for the caller to fill. */
static inline void *gw_ring_push_slot(gw_ring_t *r) {
    uint8_t *slot = r->base + (size_t)r->head * r->rec_size;
    r->head = (r->head + 1 == r->cap) ? 0 : r->head + 1;
    if (r->count < r->cap)
        r->count++;
    return slot;
}

/** Copy one record in (rec_size bytes). */
static inline void gw_ring_push(gw_ring_t *r, const void *rec) {
    memcpy(gw_ring_push_slot(r), rec, r->rec_size);
}

/** Record i (0 = oldest) or NULL when i >= count. */
static inline void *gw_ring_at(const gw_ring_t *r, uint32_t i) {
    if (i >= r->count)
        return NULL;
    uint32_t start = (r->head + r->cap - r->count) % r->cap;
    return r->base + (size_t)((start + i) % r->cap) * r->rec_size;
}

/** Record `back` steps before the newest (0 = newest) or NULL. */
static inline void *gw_ring_newest(const gw_ring_t *r, uint32_t back) {
    return back < r->count ? gw_ring_at(r, r->count - 1 - back) : NULL;
}

static inline uint32_t gw_ring_count(const gw_ring_t *r) {
    return r->count;
}

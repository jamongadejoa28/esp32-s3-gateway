/*
 * mex_core.c - pure-C MEX150 poll/write engine (see mex_core.h for the threading contract).
 *
 * Cycle of one device (poll thread):
 *   plan = fast group (+ slow group when due) or, for an OFFLINE device, the first fast block only;
 *   for each exec point i (before block i, and once after the last block):
 *       execute queued writes of this device if the validation data is fresh (published snapshot
 *       younger than MEX_FRESH_MS, or the whole fast group was just re-read in this cycle):
 *       re-validate (mex_check_write) -> FC06 -> FC03 read-back -> outcome; the slow group is
 *       (re-)appended after a write so the published snapshot reflects it;
 *       then read block i (transaction with retries); any failure aborts the cycle.
 *   success -> publish snapshot (seq+1), COMM online decision; failure -> failed-cycle count,
 *   OFFLINE after offline_after consecutive failures. Finally every write of this cycle gets its
 *   final state (monitor rule: PENDING until the post-write snapshot is published).
 */
#include "mex_core.h"

#include <string.h>

#define NONE_IDX ((size_t)-1)
#define MAX_WRITES_PER_CYCLE MEX_WRITE_QUEUE_LEN

enum { N_TX, N_RX_OK, N_EXC, N_CRC, N_TIMEOUT, N_MALFORMED };

static inline void lock(mex_core_t *c) {
    c->io.lock(c->io.ctx);
}
static inline void unlock(mex_core_t *c) {
    c->io.unlock(c->io.ctx);
}
static inline uint64_t mono(mex_core_t *c) {
    return c->io.mono_ms(c->io.ctx);
}
static inline int64_t wall(mex_core_t *c) {
    return c->io.wall_ms(c->io.ctx);
}
static inline void feed(mex_core_t *c) {
    if (c->io.feed)
        c->io.feed(c->io.ctx);
}

size_t mex_core_sizeof(void) {
    return sizeof(mex_core_t);
}

/* ------------------------------------------------------------------------------------------------ */
/* Configuration                                                                                    */

bool mex_core_port_valid(const mex_port_cfg_t *p) {
    return p && p->baud >= 1200 && p->baud <= 115200 &&
           (p->parity == 'N' || p->parity == 'E' || p->parity == 'O') && (p->stop == 1 || p->stop == 2) &&
           p->poll_ms >= 200 && p->poll_ms <= 60000 && p->timeout_ms >= 50 && p->timeout_ms <= 2000 &&
           p->gap_ms <= 100 && p->retries <= 3 && p->offline_after >= 1 && p->offline_after <= 10;
}

bool mex_core_cfg_valid(const mex_port_cfg_t *port, const mex_dev_cfg_t *devs, size_t n) {
    if (!mex_core_port_valid(port) || n > GW_MAX_DEVICES || (n && !devs))
        return false;
    for (size_t i = 0; i < n; i++) {
        const mex_dev_cfg_t *d = &devs[i];
        if (d->id >= GW_MAX_DEVICES || d->slave < 1 || d->slave > 247 ||
            !memchr(d->name, '\0', sizeof d->name))
            return false;
        if (!memchr(d->template_id, 0, sizeof(d->template_id)) ||
            (d->template_id[0] && strcmp(d->template_id, GW_DEFAULT_TEMPLATE_ID)))
            return false; /* This driver only implements MEX150, even as the catalog grows. */
        for (size_t j = 0; j < i; j++) {
            if (devs[j].id == d->id)
                return false;
            if (d->enabled && devs[j].enabled && devs[j].slave == d->slave)
                return false;
        }
    }
    return true;
}

void mex_core_init(mex_core_t *c, const mex_core_io_t *io) {
    memset(c, 0, sizeof *c);
    c->io = *io;
    c->next_cmd = 1;
    c->rr_last = GW_MAX_DEVICES - 1;
}

/* ------------------------------------------------------------------------------------------------ */
/* Command history and finalisation (caller holds the lock)                                         */

static void hist_insert(mex_core_t *c, const mex_wresult_t *r) {
    size_t slot = NONE_IDX;
    for (size_t i = 0; i < MEX_CMD_HISTORY && slot == NONE_IDX; i++) {
        if (c->hist[i].cmd == 0)
            slot = i;
    }
    if (slot == NONE_IDX) { /* evict the oldest final record; pending ones (<= queue length) stay */
        for (size_t i = 0; i < MEX_CMD_HISTORY; i++) {
            if (c->hist[i].state != MEX_W_PENDING && (slot == NONE_IDX || c->hist[i].cmd < c->hist[slot].cmd))
                slot = i;
        }
    }
    if (slot == NONE_IDX) { /* unreachable while MEX_WRITE_QUEUE_LEN < MEX_CMD_HISTORY */
        slot = 0;
        for (size_t i = 1; i < MEX_CMD_HISTORY; i++) {
            if (c->hist[i].cmd < c->hist[slot].cmd)
                slot = i;
        }
    }
    c->hist[slot] = *r;
}

static void hist_update(mex_core_t *c, const mex_wresult_t *r) {
    for (size_t i = 0; i < MEX_CMD_HISTORY; i++) {
        if (c->hist[i].cmd == r->cmd && c->hist[i].dev == r->dev) {
            c->hist[i] = *r;
            return;
        }
    }
}

_Static_assert(MEX_WRITE_QUEUE_LEN < MEX_CMD_HISTORY, "pending commands must never be evicted");

/* Final state for a queue entry: history, scratch for the on_write callback, slot freed. */
static void finalize(mex_core_t *c, mex_core_wq_t *e, mex_wstate_t state, int reason, int32_t raw_before,
                     int32_t raw_after) {
    mex_wresult_t r = {
        .cmd = e->cmd,
        .state = state,
        .reason = reason,
        .raw_after = raw_after,
        .dev = e->dev,
        .addr = e->addr,
        .raw_req = e->raw_req,
        .ts_ms = wall(c),
    };
    hist_update(c, &r);
    if (c->fin_n < MEX_WRITE_QUEUE_LEN) {
        mex_core_fin_t *f = &c->fin[c->fin_n++];
        f->res = r;
        f->raw_before = raw_before;
        memcpy(f->who, e->who, sizeof f->who);
    }
    memset(e, 0, sizeof *e);
}

/* Deliver collected final states. Poll thread (or the configuring thread), lock NOT held. */
static void flush_fin(mex_core_t *c) {
    for (size_t i = 0; i < c->fin_n; i++) {
        if (c->io.on_write)
            c->io.on_write(c->io.ctx, &c->fin[i].res, c->fin[i].raw_before, c->fin[i].who);
    }
    c->fin_n = 0;
}

/* Reject every QUEUED write of dev (lock held). */
static void reject_queued(mex_core_t *c, uint8_t dev, int reason) {
    const mex_core_dev_t *d = &c->dev[dev];
    for (size_t i = 0; i < MEX_WRITE_QUEUE_LEN; i++) {
        mex_core_wq_t *e = &c->wq[i];
        if (e->phase == MEX_WQ_QUEUED && e->dev == dev) {
            const int32_t raw = mex_snap_raw(&d->snap, e->addr);
            finalize(c, e, MEX_W_REJECTED, reason, raw, raw);
        }
    }
}

/* Oldest QUEUED entry of dev (lock held), or NULL. */
static mex_core_wq_t *oldest_queued(mex_core_t *c, uint8_t dev) {
    mex_core_wq_t *best = NULL;
    for (size_t i = 0; i < MEX_WRITE_QUEUE_LEN; i++) {
        mex_core_wq_t *e = &c->wq[i];
        if (e->phase == MEX_WQ_QUEUED && e->dev == dev && (!best || e->cmd < best->cmd))
            best = e;
    }
    return best;
}

/* ------------------------------------------------------------------------------------------------ */
/* Apply a configuration (poll thread or initial configure). Returns true if the UART line settings
 * must be (re)applied. Cancelled writes are collected in c->fin.                                   */

static const mex_dev_cfg_t *cfg_find(const mex_dev_cfg_t *devs, size_t n, uint8_t id) {
    for (size_t i = 0; i < n; i++) {
        if (devs[i].id == id)
            return &devs[i];
    }
    return NULL;
}

static bool apply_cfg(mex_core_t *c, const mex_port_cfg_t *port, const mex_dev_cfg_t *devs, size_t n,
                      bool initial) {
    lock(c);
    const uint64_t t = mono(c);
    const bool line =
        initial || c->port.baud != port->baud || c->port.parity != port->parity || c->port.stop != port->stop;
    c->port = *port;
    for (uint8_t id = 0; id < GW_MAX_DEVICES; id++) {
        const mex_dev_cfg_t *nd = cfg_find(devs, n, id);
        mex_core_dev_t *d = &c->dev[id];
        if (!nd) {
            if (d->configured) {
                reject_queued(c, id, MEX_R_CANCELLED);
                memset(d, 0, sizeof *d);
            }
            continue;
        }
        if (!d->configured) {
            memset(d, 0, sizeof *d);
            d->cfg = *nd;
            d->configured = true;
            d->comm = MEX_COMM_UNKNOWN;
            d->next_due_ms = t;
        } else if (d->cfg.slave != nd->slave || d->cfg.enabled != nd->enabled) {
            reject_queued(c, id, MEX_R_CANCELLED);
            if (d->cfg.slave != nd->slave) { /* another unit: its data must not survive (seq is kept) */
                const uint32_t seq = d->snap.seq;
                memset(&d->snap, 0, sizeof d->snap);
                d->snap.seq = seq;
            }
            d->snap.online = false;
            d->snap.slow_valid = false;
            d->snap.measurement_valid = false;
            d->comm = MEX_COMM_UNKNOWN; /* silently: no COMM event (gw_events.h) */
            d->fail_cycles = 0;
            d->last_err = 0;
            d->last_slow_ms = 0;
            d->write_since_slow = false;
            d->next_due_ms = t;
        }
        d->cfg = *nd;
        if (line)
            d->snap.measurement_valid = false;
        d->cfg.name[sizeof d->cfg.name - 1] = '\0';
    }
    unlock(c);
    return line;
}

esp_err_t mex_core_configure(mex_core_t *c, const mex_port_cfg_t *port, const mex_dev_cfg_t *devs, size_t n) {
    if (!c || !mex_core_cfg_valid(port, devs, n))
        return ESP_ERR_INVALID_ARG;
    if (c->configured)
        return ESP_ERR_INVALID_STATE;
    apply_cfg(c, port, devs, n, true);
    flush_fin(c);
    if (c->io.port_apply && c->io.port_apply(c->io.ctx, port) != 0)
        return ESP_FAIL;
    c->configured = true;
    return ESP_OK;
}

esp_err_t mex_core_reconfigure(mex_core_t *c, const mex_port_cfg_t *port, const mex_dev_cfg_t *devs,
                               size_t n) {
    if (!c || !mex_core_cfg_valid(port, devs, n))
        return ESP_ERR_INVALID_ARG;
    lock(c);
    if (!c->configured) {
        unlock(c);
        return ESP_ERR_INVALID_STATE;
    }
    c->pend_port = *port;
    memset(c->pend_devs, 0, sizeof c->pend_devs);
    if (n)
        memcpy(c->pend_devs, devs, n * sizeof *devs);
    c->pend_n = n;
    c->pend = true;
    unlock(c);
    return ESP_OK;
}

/* ------------------------------------------------------------------------------------------------ */
/* Transactions                                                                                     */

static void note(mex_core_t *c, mex_core_dev_t *d, int kind, uint64_t rtt_ms, bool has_rtt) {
    lock(c);
    mex_stats_t *s = &d->stats;
    switch (kind) {
    case N_TX:
        s->tx++;
        break;
    case N_RX_OK:
        s->rx_ok++;
        break;
    case N_EXC:
        s->exception++;
        break;
    case N_CRC:
        s->crc++;
        break;
    case N_TIMEOUT:
        s->timeout++;
        break;
    default:
        s->malformed++;
        break;
    }
    if (has_rtt) {
        const uint16_t r = rtt_ms > 0xFFFFu ? 0xFFFFu : (uint16_t)rtt_ms;
        s->rtt_last = r;
        if (r > s->rtt_max)
            s->rtt_max = r;
        d->rtt_avg_x8 = d->rtt_avg_x8 ? d->rtt_avg_x8 - d->rtt_avg_x8 / 8u + r : (uint32_t)r * 8u;
        s->rtt_avg = (uint16_t)((d->rtt_avg_x8 + 4u) / 8u);
    }
    unlock(c);
}

/* Read one response into c->rx (monitor exchange() receive loop: stop as soon as the expected length is
 * known and complete). A local echo of an FC01/FC03 request (RS485 transceivers without echo
 * suppression) is recognised exactly - a real read response never starts with unit, fc, 0x00 because
 * its byte count is non-zero and our addresses are < 256 - and skipped. */
static int receive(mex_core_t *c, const uint8_t req[MEX_REQ_LEN], uint32_t timeout_ms, size_t *n_out) {
    uint8_t *buf = c->rx;
    const size_t cap = sizeof c->rx;
    const uint64_t deadline = mono(c) + timeout_ms;
    const bool read_fc = req[1] == MEX_FC_READ_COILS || req[1] == MEX_FC_READ_HOLDING;
    bool echo_checked = false;
    size_t n = 0;
    *n_out = 0;
    for (;;) {
        size_t target = 3;
        if (n >= 3) {
            target = mex_response_expected(buf, n, req[1]);
            if (target > cap)
                target = cap;
            if (n >= target)
                break;
        }
        const uint64_t t = mono(c);
        if (t >= deadline)
            break;
        const size_t want = target - n;
        int got = c->io.read(c->io.ctx, buf + n, want, (uint32_t)(deadline - t));
        if (got < 0) {
            *n_out = n;
            return MEX_TXN_E_UART;
        }
        if ((size_t)got > want)
            got = (int)want;
        n += (size_t)got;
        if ((size_t)got < want) /* read() returns short only when its timeout elapsed */
            break;
        if (!echo_checked && n >= 3) {
            echo_checked = true;
            if (read_fc && !memcmp(buf, req, 3)) {
                const uint64_t t2 = mono(c);
                if (t2 >= deadline)
                    break;
                const size_t rest = MEX_REQ_LEN - n;
                int g = c->io.read(c->io.ctx, buf + n, rest, (uint32_t)(deadline - t2));
                if (g < 0) {
                    *n_out = n;
                    return MEX_TXN_E_UART;
                }
                if ((size_t)g > rest)
                    g = (int)rest;
                n += (size_t)g;
                if ((size_t)g < rest)
                    break;
                if (!memcmp(buf, req, MEX_REQ_LEN))
                    n = 0; /* our own request: drop it and wait for the slave */
            }
        }
    }
    *n_out = n;
    return 0;
}

/* One attempt: gap, request, receive, parse, count. */
static int attempt(mex_core_t *c, mex_core_dev_t *d, uint8_t slave, uint8_t fc, uint16_t pdu, uint16_t val,
                   uint16_t *values, size_t cap) {
    uint8_t req[MEX_REQ_LEN];
    mex_request(slave, fc, pdu, val, req);
    c->io.gap(c->io.ctx, c->port.gap_ms);
    const uint64_t t0 = mono(c);
    if (c->io.write(c->io.ctx, req, sizeof req) != 0)
        return MEX_TXN_E_UART;
    note(c, d, N_TX, 0, false);
    size_t n = 0;
    if (receive(c, req, c->port.timeout_ms, &n) != 0) {
        note(c, d, N_TIMEOUT, 0, false); /* sent but no answer could be read: keeps tx == sum of outcomes */
        return MEX_TXN_E_UART;
    }
    const uint64_t t1 = mono(c);
    if (n == 0) {
        note(c, d, N_TIMEOUT, 0, false);
        return MEX_TXN_E_TIMEOUT;
    }
    const int r = mex_response(req, c->rx, n, values, cap);
    if (r == MEX_RESP_OK)
        note(c, d, N_RX_OK, t1 - t0, true);
    else if (r > 0)
        note(c, d, N_EXC, t1 - t0, true);
    else if (!mex_frame_crc_ok(c->rx, n))
        note(c, d, N_CRC, 0, false);
    else
        note(c, d, N_MALFORMED, 0, false);
    return r;
}

/* Transaction with up to `retries` repetitions. An exception is a definitive answer and is not retried. */
static int txn(mex_core_t *c, mex_core_dev_t *d, unsigned retries, uint8_t slave, uint8_t fc, uint16_t pdu,
               uint16_t val, uint16_t *values, size_t cap) {
    int r = MEX_TXN_E_TIMEOUT;
    for (unsigned a = 0; a <= retries; a++) {
        feed(c);
        r = attempt(c, d, slave, fc, pdu, val, values, cap);
        if (r >= 0)
            return r;
    }
    return r;
}

/* ------------------------------------------------------------------------------------------------ */
/* Poll cycle                                                                                       */

typedef struct {
    uint8_t dev;
    uint8_t slave;
    mex_snapshot_t next; /* published snapshot + data read in this cycle */
    mex_block_t plan[MEX_CORE_PLAN_CAP];
    size_t n;
    size_t slow_at;       /* index of the latest slow group in plan, NONE_IDX if none */
    size_t last_write_at; /* exec point of the latest sent write, NONE_IDX if none */
    unsigned writes;      /* writes sent in this cycle */
} cycle_t;

/* Execute queued writes of the cycle's device at exec point i. */
static void exec_writes(mex_core_t *c, cycle_t *cy, size_t i, bool fast_done) {
    mex_core_dev_t *d = &c->dev[cy->dev];
    while (cy->writes < MAX_WRITES_PER_CYCLE) {
        const uint64_t t = mono(c);
        lock(c);
        mex_core_wq_t *e = oldest_queued(c, cy->dev);
        if (!e || !(fast_done || mex_fresh(&d->snap, t))) {
            unlock(c); /* nothing to do, or validation data not fresh yet (deferred) */
            return;
        }
        /* Re-validate right before sending, against the newest data (published + this cycle). */
        const int32_t raw_before = mex_snap_raw(&cy->next, e->addr);
        const mex_reason_t reason = mex_check_write(e->addr, e->raw_req, true, mex_running(&cy->next));
        if (reason != MEX_R_OK) {
            finalize(c, e, MEX_W_REJECTED, reason, raw_before, raw_before);
            unlock(c);
            flush_fin(c);
            continue;
        }
        e->phase = MEX_WQ_SENT;
        e->raw_before = raw_before;
        const uint16_t addr = e->addr;
        const int32_t raw_req = e->raw_req;
        unlock(c);

        const mex_reg_t *r = mex_reg_find(addr);
        const uint16_t pdu = (uint16_t)(addr - MEX_ADDR_BASE - 1);
        const int ack = txn(c, d, c->port.retries, cy->slave, MEX_FC_WRITE_SINGLE, pdu,
                            mex_reg_encode(r, raw_req), NULL, 0);
        uint16_t v = 0;
        const int rb = txn(c, d, c->port.retries, cy->slave, MEX_FC_READ_HOLDING, pdu, 1, &v, 1);
        mex_wstate_t st;
        int why = MEX_R_OK;
        int32_t raw_after = raw_before;
        if (rb == MEX_RESP_OK) {
            raw_after = mex_reg_decode(r, v);
            cy->next.regs[mex_reg_index(addr)] = v; /* the published snapshot shows the read-back */
        }
        if (ack > 0) {
            st = MEX_W_REJECTED;
            why = MEX_R_EXCEPTION(ack);
        } else if (rb == MEX_RESP_OK && mex_reg_write_matches(r, raw_req, raw_after)) {
            st = MEX_W_APPLIED; /* monitor: a matching read-back confirms even a lost ack */
        } else {
            st = MEX_W_UNCERTAIN;
            why = ack < 0 ? MEX_R_NO_ACK : MEX_R_VERIFY;
        }
        lock(c);
        e->state = (uint8_t)st;
        e->reason = why;
        e->raw_after = raw_after;
        e->have_read = rb == MEX_RESP_OK;
        unlock(c);

        cy->writes++;
        cy->last_write_at = i;
        /* The slow group must be read after the write so the post-write snapshot is complete. */
        if (cy->slow_at == NONE_IDX || cy->slow_at < i) {
            if (cy->n + MEX_SLOW_BLOCKS <= MEX_CORE_PLAN_CAP) {
                cy->slow_at = cy->n;
                for (size_t k = 0; k < MEX_SLOW_BLOCKS; k++)
                    cy->plan[cy->n++] = mex_slow_blocks[k];
            }
        }
    }
}

static void run_cycle(mex_core_t *c, uint8_t di) {
    mex_core_dev_t *d = &c->dev[di];
    cycle_t cy = {.dev = di, .slow_at = NONE_IDX, .last_write_at = NONE_IDX};
    const uint64_t start = mono(c);

    lock(c);
    cy.slave = d->cfg.slave;
    cy.next = d->snap;
    const uint8_t comm0 = d->comm;
    unlock(c);

    bool probe = comm0 == MEX_COMM_OFFLINE;
    const bool slow_due =
        comm0 != MEX_COMM_ONLINE || mex_plan_slow_due(start, d->last_slow_ms, d->write_since_slow);
    cy.n = mex_plan_cycle(!probe, slow_due, cy.plan, MEX_CORE_PLAN_CAP);
    if (!probe && slow_due)
        cy.slow_at = cy.n - MEX_SLOW_BLOCKS;

    bool ok = true;
    int last_err = 0;
    uint16_t values[MEX_MAX_READ];
    for (size_t i = 0;; i++) {
        if (!probe)
            exec_writes(c, &cy, i, i >= MEX_FAST_BLOCKS);
        if (i >= cy.n)
            break;
        const mex_block_t *b = &cy.plan[i];
        memset(values, 0, sizeof values);
        /* An offline probe is a single attempt: it is repeated every MEX_OFFLINE_POLL_MS anyway, and
         * retries would only keep the bus from the devices that are online. */
        const int r = txn(c, d, probe ? 0u : c->port.retries, cy.slave, b->fc, b->start, b->count, values,
                          MEX_MAX_READ);
        if (r != MEX_RESP_OK) {
            ok = false;
            last_err = r;
            break;
        }
        mex_block_store(b, values, &cy.next);
        if (probe) { /* the offline probe answered: read everything (incl. slow) in this same cycle */
            probe = false;
            cy.n = mex_plan_cycle(true, true, cy.plan, MEX_CORE_PLAN_CAP);
            cy.slow_at = cy.n - MEX_SLOW_BLOCKS;
        }
    }

    const uint64_t t = mono(c);
    const int64_t w = wall(c);
    bool comm_evt = false, snap_evt = false, slow_fresh = false;
    uint32_t seq = 0;

    lock(c);
    d->last_err = (int16_t)last_err;
    if (ok) {
        slow_fresh = cy.slow_at != NONE_IDX;
        cy.next.seq = d->snap.seq + 1 ? d->snap.seq + 1 : 1;
        cy.next.online = true;
        cy.next.measurement_valid =
            d->snap.measurement_valid || cy.next.regs[36] != 0 || cy.next.regs[37] != 0;
        cy.next.mono_ms = t;
        cy.next.wall_ms = w;
        cy.next.slow_valid = d->snap.slow_valid || slow_fresh;
        d->snap = cy.next;
        seq = cy.next.seq;
        snap_evt = true;
        if (slow_fresh) {
            d->last_slow_ms = t ? t : 1;
            d->write_since_slow = cy.last_write_at != NONE_IDX && cy.slow_at < cy.last_write_at;
        } else if (cy.last_write_at != NONE_IDX) {
            d->write_since_slow = true;
        }
        d->stats.cycles++;
        d->fail_cycles = 0;
        if (d->comm != MEX_COMM_ONLINE) {
            d->comm = MEX_COMM_ONLINE;
            d->stats.online_since_ms = w;
            comm_evt = true;
        }
    } else {
        /* A short reboot can recover before offline_after failures. Re-arm measurement readiness
         * on any interrupted cycle so its startup zeros cannot inherit the old connection's flag. */
        d->snap.measurement_valid = false;
        if (cy.last_write_at != NONE_IDX)
            d->write_since_slow = true;
        if (d->fail_cycles < UINT8_MAX)
            d->fail_cycles++;
        if (d->comm != MEX_COMM_OFFLINE && d->fail_cycles >= c->port.offline_after) {
            d->comm = MEX_COMM_OFFLINE;
            d->stats.offline_count++;
            d->snap.online = false;
            d->snap.slow_valid = false;
            d->snap.measurement_valid = false;
            comm_evt = true;
        }
    }
    const bool online = d->comm == MEX_COMM_ONLINE;
    const uint32_t offline_count = d->stats.offline_count;
    d->next_due_ms = start + (d->comm == MEX_COMM_OFFLINE ? MEX_OFFLINE_POLL_MS : c->port.poll_ms);

    /* Final states of this cycle's writes (after the post-write snapshot was published). */
    for (size_t k = 0; k < MEX_WRITE_QUEUE_LEN; k++) {
        mex_core_wq_t *e = &c->wq[k];
        if (e->phase != MEX_WQ_SENT || e->dev != di)
            continue;
        /* gw_events.h: raw_after == raw_before when nothing was read back */
        finalize(c, e, (mex_wstate_t)e->state, e->reason, e->raw_before,
                 e->have_read ? e->raw_after : e->raw_before);
    }
    if (!ok)
        reject_queued(c, di, MEX_R_OFFLINE);
    unlock(c);

    if (comm_evt && c->io.on_comm)
        c->io.on_comm(c->io.ctx, di, online, last_err, offline_count, w);
    if (snap_evt && c->io.on_snapshot)
        c->io.on_snapshot(c->io.ctx, di, seq, t, slow_fresh);
    flush_fin(c);
}

/* ------------------------------------------------------------------------------------------------ */
/* Scheduler                                                                                        */

uint32_t mex_core_run_once(mex_core_t *c) {
    feed(c);
    if (!c->configured)
        return MEX_CORE_IDLE_MAX_MS;

    mex_port_cfg_t port;
    mex_dev_cfg_t devs[GW_MAX_DEVICES];
    size_t n = 0;
    bool apply = false;
    lock(c);
    if (c->pend) {
        port = c->pend_port;
        n = c->pend_n;
        memcpy(devs, c->pend_devs, sizeof devs);
        c->pend = false;
        apply = true;
    }
    unlock(c);
    if (apply) {
        if (apply_cfg(c, &port, devs, n, false) && c->io.port_apply)
            (void)c->io.port_apply(c->io.ctx, &port); /* a failure shows up as failed transactions */
        flush_fin(c);
    }

    const uint64_t t = mono(c);
    int pick = -1;
    uint8_t why = MEX_PICK_DUE;
    uint32_t wait = MEX_CORE_IDLE_MAX_MS;
    lock(c);
    /* the device of the oldest queued write */
    int wdev = -1;
    uint32_t best_cmd = 0;
    for (size_t i = 0; i < MEX_WRITE_QUEUE_LEN; i++) {
        mex_core_wq_t *e = &c->wq[i];
        if (e->phase != MEX_WQ_QUEUED)
            continue;
        const mex_core_dev_t *d = &c->dev[e->dev];
        if (!d->configured || !d->cfg.enabled) { /* defensive: cancelled by apply_cfg normally */
            const int32_t raw = mex_snap_raw(&d->snap, e->addr);
            finalize(c, e, MEX_W_REJECTED, MEX_R_CANCELLED, raw, raw);
            continue;
        }
        if (wdev < 0 || e->cmd < best_cmd) {
            wdev = e->dev;
            best_cmd = e->cmd;
        }
    }
    /* the most overdue due device overall, and the most overdue one that is not OFFLINE; round-robin
     * after the last one served on ties */
    int due_any = -1, due_live = -1;
    bool other_due = false;
    uint64_t best_any = UINT64_MAX, best_live = UINT64_MAX;
    for (unsigned k = 1; k <= GW_MAX_DEVICES; k++) {
        const unsigned id = (c->rr_last + k) % GW_MAX_DEVICES;
        const mex_core_dev_t *d = &c->dev[id];
        if (!d->configured || !d->cfg.enabled)
            continue;
        if (d->next_due_ms > t) {
            if (d->next_due_ms - t < wait)
                wait = (uint32_t)(d->next_due_ms - t);
            continue;
        }
        if ((int)id != wdev)
            other_due = true;
        if (d->next_due_ms < best_any) {
            best_any = d->next_due_ms;
            due_any = (int)id;
        }
        if (d->comm != MEX_COMM_OFFLINE && d->next_due_ms < best_live) {
            best_live = d->next_due_ms;
            due_live = (int)id;
        }
    }
    if (wdev >= 0 && !(c->last_pick == MEX_PICK_WRITE && other_due)) {
        pick = wdev;
        why = MEX_PICK_WRITE;
    } else {
        pick = (c->last_pick == MEX_PICK_PROBE && due_live >= 0) ? due_live : due_any;
        if (pick >= 0 && c->dev[pick].comm == MEX_COMM_OFFLINE)
            why = MEX_PICK_PROBE;
    }
    unlock(c);
    flush_fin(c);

    if (pick < 0)
        return wait ? wait : 1;
    c->rr_last = (uint8_t)pick;
    c->last_pick = why;
    run_cycle(c, (uint8_t)pick);
    return 0;
}

/* ------------------------------------------------------------------------------------------------ */
/* API side                                                                                         */

esp_err_t mex_core_write_submit(mex_core_t *c, uint8_t dev, uint16_t addr, int32_t raw, const char *who,
                                mex_wresult_t *out) {
    if (!c || !out)
        return ESP_ERR_INVALID_ARG;
    memset(out, 0, sizeof *out);
    out->state = MEX_W_REJECTED;
    out->dev = dev;
    out->addr = addr;
    out->raw_req = raw;
    if (dev >= GW_MAX_DEVICES)
        return ESP_ERR_INVALID_ARG;

    char who_c[GW_USER_NAME_SZ];
    gw_strlcpy(who_c, who ? who : "", sizeof who_c);

    lock(c);
    mex_core_dev_t *d = &c->dev[dev];
    if (!c->configured || !d->configured) {
        unlock(c);
        return ESP_ERR_INVALID_ARG;
    }
    const uint64_t t = mono(c);
    const int64_t w = wall(c);
    /* Enqueue check. Freshness: a snapshot < MEX_FRESH_MS old (DESIGN §9). Only when the configured poll
     * period itself is longer than MEX_FRESH_MS (data is then normally older) is an ONLINE device whose
     * last cycle succeeded accepted with a snapshot younger than poll_ms + MEX_FRESH_MS (one missed
     * period). The authoritative check right before sending always requires data younger than
     * MEX_FRESH_MS (DECISIONS.md, stream A / Contract issues). */
    const bool fresh = mex_fresh(&d->snap, t) ||
                       (c->port.poll_ms > MEX_FRESH_MS && d->cfg.enabled && d->comm == MEX_COMM_ONLINE &&
                        d->fail_cycles == 0 && d->snap.online && d->snap.mono_ms && t >= d->snap.mono_ms &&
                        t - d->snap.mono_ms < (uint64_t)c->port.poll_ms + MEX_FRESH_MS);
    const int32_t raw_before = mex_snap_raw(&d->snap, addr);
    mex_reason_t reason = mex_check_write(addr, raw, fresh, mex_running(&d->snap));
    mex_core_wq_t *slot = NULL;
    if (reason == MEX_R_OK) {
        for (size_t i = 0; i < MEX_WRITE_QUEUE_LEN && !slot; i++) {
            if (c->wq[i].phase == MEX_WQ_FREE)
                slot = &c->wq[i];
        }
        if (!slot)
            reason = MEX_R_BUSY;
    }
    out->raw_after = raw_before;
    out->ts_ms = w;
    if (reason != MEX_R_OK) {
        out->reason = reason;
        unlock(c);
        if (c->io.on_write)
            c->io.on_write(c->io.ctx, out, raw_before, who_c);
        return reason == MEX_R_BUSY ? ESP_ERR_NO_MEM : ESP_OK;
    }
    uint32_t cmd = c->next_cmd++;
    if (!cmd) /* wrapped: 0 means "not queued" */
        cmd = c->next_cmd++;
    *slot = (mex_core_wq_t){.cmd = cmd, .phase = MEX_WQ_QUEUED, .dev = dev, .addr = addr, .raw_req = raw};
    memcpy(slot->who, who_c, sizeof slot->who);
    out->cmd = cmd;
    out->state = MEX_W_PENDING;
    out->reason = MEX_R_OK;
    hist_insert(c, out);
    unlock(c);
    return ESP_OK;
}

bool mex_core_command(mex_core_t *c, uint8_t dev, uint32_t cmd, mex_wresult_t *out) {
    if (!c || !out)
        return false;
    memset(out, 0, sizeof *out);
    if (!cmd)
        return false;
    bool found = false;
    lock(c);
    for (size_t i = 0; i < MEX_CMD_HISTORY; i++) {
        if (c->hist[i].cmd == cmd && c->hist[i].dev == dev) {
            *out = c->hist[i];
            found = true;
            break;
        }
    }
    unlock(c);
    return found;
}

bool mex_core_snapshot(mex_core_t *c, uint8_t dev, mex_snapshot_t *out) {
    if (!out)
        return false;
    memset(out, 0, sizeof *out);
    if (!c || dev >= GW_MAX_DEVICES)
        return false;
    bool ok = false;
    lock(c);
    if (c->dev[dev].configured) {
        *out = c->dev[dev].snap;
        ok = true;
    }
    unlock(c);
    return ok;
}

void mex_core_stats(mex_core_t *c, uint8_t dev, mex_stats_t *out, bool reset) {
    if (!out)
        return;
    memset(out, 0, sizeof *out);
    if (!c || dev >= GW_MAX_DEVICES)
        return;
    lock(c);
    mex_core_dev_t *d = &c->dev[dev];
    if (d->configured) {
        *out = d->stats;
        if (reset) {
            const int64_t since = d->stats.online_since_ms;
            memset(&d->stats, 0, sizeof d->stats);
            d->stats.online_since_ms = since;
            d->rtt_avg_x8 = 0;
        }
    }
    unlock(c);
}

uint8_t mex_core_comm(mex_core_t *c, uint8_t dev) {
    if (!c || dev >= GW_MAX_DEVICES)
        return MEX_COMM_UNKNOWN;
    lock(c);
    const uint8_t s = c->dev[dev].configured ? c->dev[dev].comm : (uint8_t)MEX_COMM_UNKNOWN;
    unlock(c);
    return s;
}

/* ------------------------------------------------------------------------------------------------ */
/* Bounded receive on top of a per-chunk-timeout driver                                             */

int mex_rx_bounded(const mex_rx_ops_t *ops, uint8_t *buf, size_t want, uint32_t timeout) {
    if (!ops || !ops->now || !ops->avail || !ops->recv || !buf)
        return MEX_TXN_E_UART;
    const uint32_t start = ops->now(ops->ctx);
    size_t got = 0;
    bool block = false; /* the driver had less than it reported: wait for the next byte instead */
    while (got < want) {
        size_t n = want - got;
        uint32_t wait = 0;
        int avail = 0;
        if (!block) {
            avail = ops->avail(ops->ctx);
            if (avail < 0)
                return got ? (int)got : MEX_TXN_E_UART;
        }
        if (avail > 0) {
            if ((size_t)avail < n)
                n = (size_t)avail;
        } else {
            const uint32_t elapsed = ops->now(ops->ctx) - start; /* unsigned: wrap-safe */
            if (elapsed >= timeout)
                break;
            wait = timeout - elapsed;
            n = 1; /* one chunk -> the driver waits at most `wait` in total */
        }
        int r = ops->recv(ops->ctx, buf + got, n, wait);
        if (r < 0)
            return got ? (int)got : MEX_TXN_E_UART;
        if ((size_t)r > n)
            r = (int)n;
        got += (size_t)r;
        block = wait == 0 && (size_t)r < n;
        if (wait && r == 0) /* timed out waiting for a byte; the loop head re-checks the deadline */
            block = true;
    }
    return (int)got;
}

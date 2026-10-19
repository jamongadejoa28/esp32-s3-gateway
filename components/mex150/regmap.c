/*
 * regmap.c - tables and helpers generated from regmap.def (pure C, host-safe; contract: mex150/regmap.h).
 */
#include "mex150/regmap.h"

#include <math.h>
#include <stdio.h>
#include <string.h>

/* ---- Tables (expanded from regmap.def via regmap_x.h) ---- */

const mex_reg_t mex_regs[MEX_REG_COUNT] = {
#define REG(key_, addr_, scale_, sign_, access_, min_, max_, disabled_, flags_, group_, unit_, ko_, en_)        \
    [MEX_REG_##key_] = {.key = #key_,                                                                        \
                        .addr = (addr_),                                                                     \
                        .scale = (scale_),                                                                   \
                        .is_signed = (sign_),                                                                \
                        .writable = (access_),                                                               \
                        .min = (min_),                                                                       \
                        .max = (max_),                                                                       \
                        .disabled = (disabled_),                                                             \
                        .flags = (uint32_t)(flags_),                                                         \
                        .group = (group_),                                                                   \
                        .unit = (unit_),                                                                     \
                        .ko = (ko_),                                                                         \
                        .en = (en_)},
#include "mex150/regmap_x.h"
};

const mex_bit_t mex_bits[MEX_BIT_COUNT] = {
#define REGBIT(key_, addr_, bit_, ko_, en_)                                                                  \
    [MEX_BIT_##key_] = {.key = #key_, .addr = (addr_), .lsb = (bit_), .width = 1, .unit = "", .ko = (ko_), .en = (en_)},
#define FIELD(key_, addr_, lsb_, width_, unit_, ko_, en_)                                                     \
    [MEX_BIT_##key_] = {                                                                                     \
        .key = #key_, .addr = (addr_), .lsb = (lsb_), .width = (width_), .unit = (unit_), .ko = (ko_), .en = (en_)},
#include "mex150/regmap_x.h"
};

const mex_coil_t mex_coils[MEX_COIL_COUNT] = {
#define COIL(key_, n_, group_, ko_, en_) [MEX_COIL_##key_] = {.key = #key_, .n = (n_), .group = (group_), .ko = (ko_), .en = (en_)},
#include "mex150/regmap_x.h"
};

const mex_enum_t mex_enums[MEX_ENUM_COUNT] = {
#define ENUM(regkey_, value_, ko_, en_)                                                                      \
    [MEX_ENUM_##regkey_##_##value_] = {.reg = MEX_REG_##regkey_, .value = (value_), .ko = (ko_), .en = (en_)},
#include "mex150/regmap_x.h"
};

/* Address -> (row index + 1); 0 = no REG row. A REG address outside 40000..40059 is a compile error
 * (designator out of bounds); a duplicate address is caught by tests/test_contracts.py. */
static const uint8_t s_reg_by_index[MEX_REGS_LEN] = {
#define REG(key_, addr_, ...) [(addr_) - MEX_ADDR_BASE] = (uint8_t)(MEX_REG_##key_ + 1),
#include "mex150/regmap_x.h"
};

_Static_assert(MEX_REG_COUNT < 255, "s_reg_by_index stores row index + 1 in a uint8_t");

/* ---- Lookups ---- */

const mex_reg_t *mex_reg_find(uint16_t addr) {
    if (addr < MEX_ADDR_BASE || addr >= MEX_ADDR_BASE + MEX_REGS_LEN)
        return NULL;
    const uint8_t i = s_reg_by_index[addr - MEX_ADDR_BASE];
    return i ? &mex_regs[i - 1] : NULL;
}

const mex_reg_t *mex_reg_find_key(const char *key) {
    if (!key)
        return NULL;
    for (size_t i = 0; i < MEX_REG_COUNT; i++) {
        if (!strcmp(mex_regs[i].key, key))
            return &mex_regs[i];
    }
    return NULL;
}

const mex_coil_t *mex_coil_find(uint8_t n) {
    if (n < 1 || n > MEX_COILS_LEN)
        return NULL;
    if (n <= MEX_COIL_COUNT && mex_coils[n - 1].n == n) /* regmap.def lists coils 1..32 in order */
        return &mex_coils[n - 1];
    for (size_t i = 0; i < MEX_COIL_COUNT; i++) {
        if (mex_coils[i].n == n)
            return &mex_coils[i];
    }
    return NULL;
}

/* ---- Value conversion ---- */

int32_t mex_reg_decode(const mex_reg_t *r, uint16_t wire) {
    if (r && r->is_signed)
        return (int32_t)(int16_t)wire;
    return (int32_t)wire;
}

uint16_t mex_reg_encode(const mex_reg_t *r, int32_t raw) {
    if (r && (r->flags & MEX_F_RUNBIT))
        return raw ? 1u : 0u;
    /* Two's complement truncation is the wire format for signed rows; unsigned rows are validated to
     * 0..65535 before encoding. */
    return (uint16_t)(uint32_t)raw;
}

bool mex_reg_write_matches(const mex_reg_t *r, int32_t requested, int32_t read_raw) {
    if (!r)
        return false;
    if (r->flags & MEX_F_RUNBIT)
        return ((read_raw & 0xFF) != 0) == (requested != 0);
    return read_raw == requested;
}

uint32_t mex_bit_get(const mex_bit_t *b, uint16_t wire) {
    if (!b || b->width == 0 || b->lsb >= 16)
        return 0;
    const unsigned width = b->width > 16u - b->lsb ? 16u - b->lsb : b->width;
    const uint32_t mask = (width >= 32u) ? 0xFFFFFFFFu : ((1u << width) - 1u);
    return ((uint32_t)wire >> b->lsb) & mask;
}

bool mex_reg_is_disabled(const mex_reg_t *r, int32_t raw) {
    return r && r->disabled != MEX_DIS_NONE && raw == r->disabled;
}

mex_reason_t mex_reg_check_value(const mex_reg_t *r, int32_t raw) {
    if (!r)
        return MEX_R_UNKNOWN;
    if (!r->writable)
        return MEX_R_READONLY;
    if (r->flags & MEX_F_RUNBIT)
        return (raw == 0 || raw == 1) ? MEX_R_OK : MEX_R_RANGE;
    if (mex_reg_is_disabled(r, raw))
        return MEX_R_OK;
    return (raw >= r->min && raw <= r->max) ? MEX_R_OK : MEX_R_RANGE;
}

bool mex_reg_from_value(const mex_reg_t *r, double value, int32_t *raw) {
    if (!r || !raw || !isfinite(value))
        return false;
    const double scaled = value * (double)(r->scale ? r->scale : 1u);
    if (!(scaled >= (double)INT32_MIN - 0.5 && scaled <= (double)INT32_MAX + 0.5))
        return false;
    const double rounded = round(scaled);
    if (rounded < (double)INT32_MIN || rounded > (double)INT32_MAX)
        return false;
    if (fabs(scaled - rounded) > 1e-6)
        return false;
    *raw = (int32_t)rounded;
    return true;
}

int mex_reg_format(const mex_reg_t *r, int32_t raw, char *out, size_t cap) {
    if (!r || !out || cap == 0)
        return -1;
    int n;
    if (r->scale == 10) {
        const int64_t v = raw;
        const uint64_t a = (uint64_t)(v < 0 ? -v : v);
        n = snprintf(out, cap, "%s%llu.%llu", v < 0 ? "-" : "", (unsigned long long)(a / 10u),
                     (unsigned long long)(a % 10u));
    } else if (r->scale <= 1) {
        n = snprintf(out, cap, "%ld", (long)raw);
    } else {
        /* Generic decimal scale (not used by the MEX150 map; kept correct for any power of ten). */
        unsigned digits = 0;
        uint64_t div = 1;
        for (unsigned s = r->scale; s > 1; s /= 10u) {
            digits++;
            div *= 10u;
        }
        const int64_t v = raw;
        const uint64_t a = (uint64_t)(v < 0 ? -v : v);
        n = snprintf(out, cap, "%s%llu.%0*llu", v < 0 ? "-" : "", (unsigned long long)(a / div), (int)digits,
                     (unsigned long long)(a % div));
    }
    if (n < 0 || (size_t)n >= cap) {
        out[0] = '\0';
        return -1;
    }
    return n;
}

/* ---- Names ---- */

const char *mex_group_name(mex_group_t g) {
    static const char *const names[MEX_GRP_COUNT] = {
        [MEX_GRP_STATUS] = "status",       [MEX_GRP_CONTROL] = "control", [MEX_GRP_SETPOINT] = "setpoint",
        [MEX_GRP_DEVIATION] = "deviation", [MEX_GRP_DELAY] = "delay",     [MEX_GRP_CALIBRATION] = "calibration",
        [MEX_GRP_LIMITS] = "limits",       [MEX_GRP_OPTIONS] = "options", [MEX_GRP_INFO] = "info",
        [MEX_GRP_ALARM] = "alarm",
    };
    return ((unsigned)g < MEX_GRP_COUNT) ? names[g] : "unknown";
}

static const char *reason_literal(int reason) {
    switch (reason) {
    case MEX_R_OK:
        return "ok";
    case MEX_R_UNKNOWN:
        return "unknown_register";
    case MEX_R_READONLY:
        return "readonly";
    case MEX_R_RANGE:
        return "range";
    case MEX_R_INTERLOCK:
        return "running_interlock";
    case MEX_R_OFFLINE:
        return "offline";
    case MEX_R_BUSY:
        return "busy";
    case MEX_R_NO_ACK:
        return "no_ack";
    case MEX_R_VERIFY:
        return "verify_mismatch";
    case MEX_R_CANCELLED:
        return "cancelled";
    default:
        return "internal";
    }
}

const char *mex_reason_name(int reason, char *buf, size_t cap) {
    if (reason > MEX_R_EXCEPTION_BASE && reason <= MEX_R_EXCEPTION_BASE + 255) {
        if (buf && cap) {
            const int n = snprintf(buf, cap, "exception:%d", reason - MEX_R_EXCEPTION_BASE);
            if (n > 0 && (size_t)n < cap)
                return buf;
        }
        /* Buffer missing/too small: a static name keeps the reason class visible. */
        return "exception";
    }
    const char *lit = reason_literal(reason);
    const size_t len = strlen(lit);
    if (buf && len < cap) {
        memcpy(buf, lit, len + 1);
        return buf;
    }
    /* Too small for the name (MEX_REASON_NAME_SZ always fits): the static literal is returned instead
     * of a truncated copy (callers use the return value). */
    return lit;
}

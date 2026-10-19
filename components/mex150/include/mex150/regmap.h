/*
 * regmap.h - typed view of regmap.def (pure C, host-safe).
 *
 * Terminology used across the project (one convention, also docs/API.md §1 "Numbers"):
 *   wire  - the uint16_t exchanged on Modbus / stored in mex_snapshot_t.regs[]
 *   raw   - the decoded register word at register scale: mex_reg_decode() = sign extension for
 *           signed rows (40021, 40022, 40036), otherwise the wire word unchanged, i.e. the FULL
 *           16-bit word for bitfield rows and for 40005 (bit 0 run, bits 15..8 delay seconds).
 *           Every READ path uses raw: REST live.regs / write-result "raw" / command "raw", WS
 *           snap.r and write.raw, alarm values, history, SNMP Integer32 columns, events, audit.
 *   write request raw - what a writer asks for (REST {"raw"}, mex_service_write(), SNMP SET):
 *           equal to raw for every row except MEX_F_RUNBIT rows, where it is the run bit 0/1
 *           (the row's min..max). Validation (mex_reg_check_value, mex_check_write) checks write
 *           request raws; read-back verification uses mex_reg_write_matches().
 *   value - raw / scale as a decimal number (23.5); REST "value" and the UI use value.
 * Tables are const, in flash, and safe to read from any task.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MEX_ADDR_BASE 40000 /* regs[] index = addr - MEX_ADDR_BASE */
#define MEX_REGS_LEN 60     /* mex_snapshot_t.regs[] covers 40000..40059 (index 0 unused) */
#define MEX_COILS_LEN 32
#define MEX_DIS_NONE INT32_MIN /* "no disabled sentinel" */
#define MEX_REGMAP_VERSION 1   /* bump on any regmap.def change that alters keys/addresses */

/* Row flags */
#define MEX_F_STOPPED 0x01u /* writable only while the unit is stopped (monitor interlock) */
#define MEX_F_SNMP_RW 0x02u /* writable through SNMP mexSetpointTable */
#define MEX_F_RUNBIT 0x04u  /* 40005: running = (raw & 0xFF) != 0; write request 0/1; verify low byte */
#define MEX_F_BITS 0x08u    /* bitfield word; described by REGBIT/FIELD rows */

typedef enum {
    MEX_GRP_STATUS = 0,
    MEX_GRP_CONTROL,
    MEX_GRP_SETPOINT,
    MEX_GRP_DEVIATION,
    MEX_GRP_DELAY,
    MEX_GRP_CALIBRATION,
    MEX_GRP_LIMITS,
    MEX_GRP_OPTIONS,
    MEX_GRP_INFO,
    MEX_GRP_ALARM, /* coils 17..32 */
    MEX_GRP_COUNT
} mex_group_t;

/**
 * Write / validation outcome reasons (mex_wresult_t.reason, gw_evt_write_t.reason, REST "reason").
 * Wire names (mex_reason_name): see each entry.
 */
typedef enum {
    MEX_R_OK = 0,
    MEX_R_UNKNOWN = 1,            /* "unknown_register": address not a REG row          -> REST 404 */
    MEX_R_READONLY = 2,           /* "readonly"                                          -> 409 rejected */
    MEX_R_RANGE = 3,              /* "range": outside min..max and not the sentinel      -> 409 rejected */
    MEX_R_INTERLOCK = 4,          /* "running_interlock": STOPPED row while running      -> 409 rejected */
    MEX_R_OFFLINE = 5,            /* "offline": device offline or snapshot older than 3 s -> 409 rejected */
    MEX_R_BUSY = 6,               /* "busy": write queue full                             -> 503 */
    MEX_R_NO_ACK = 7,             /* "no_ack": write sent, no/malformed reply              -> uncertain */
    MEX_R_VERIFY = 8,             /* "verify_mismatch": read-back differs or failed        -> uncertain */
    MEX_R_CANCELLED = 9,          /* "cancelled": device reconfigured/disabled before send -> 409 rejected */
    MEX_R_EXCEPTION_BASE = 0x100, /* + Modbus exception code: "exception:N"       -> 409 rejected */
} mex_reason_t;

#define MEX_R_EXCEPTION(code) (MEX_R_EXCEPTION_BASE + (int)(code))

/** Holding register descriptor (REG row). */
typedef struct {
    const char *key; /* stable identifier, e.g. "set_temp" (REST meta, SNMP, MIB names) */
    uint16_t addr;   /* 4xxxx */
    uint16_t scale;  /* 1 or 10 */
    bool is_signed;
    bool writable;
    int32_t min, max; /* raw, inclusive */
    int32_t disabled; /* raw sentinel or MEX_DIS_NONE */
    uint32_t flags;   /* MEX_F_* */
    mex_group_t group;
    const char *unit; /* UTF-8, "" if none */
    const char *ko;   /* UTF-8 Korean name (verbatim from the map) */
    const char *en;
} mex_reg_t;

/** Bit or multi-bit field of a register (BIT row: width 1, FIELD row: width > 1). */
typedef struct {
    const char *key;
    uint16_t addr;
    uint8_t lsb;
    uint8_t width;
    const char *unit;
    const char *ko;
    const char *en;
} mex_bit_t;

/** Coil descriptor. */
typedef struct {
    const char *key;
    uint8_t n; /* 1..32; bit (n-1) of mex_snapshot_t.coils */
    mex_group_t group;
    const char *ko;
    const char *en;
} mex_coil_t;

/* IDs, in regmap.def order. */
typedef enum {
#define REG(key, ...) MEX_REG_##key,
#include "mex150/regmap_x.h"
    MEX_REG_COUNT
} mex_reg_id_t;

typedef enum {
#define REGBIT(key, ...) MEX_BIT_##key,
#define FIELD(key, ...) MEX_BIT_##key,
#include "mex150/regmap_x.h"
    MEX_BIT_COUNT
} mex_bit_id_t;

typedef enum {
#define COIL(key, ...) MEX_COIL_##key,
#include "mex150/regmap_x.h"
    MEX_COIL_COUNT
} mex_coil_id_t;

/** Value label (ENUM row). */
typedef struct {
    mex_reg_id_t reg;
    int32_t value; /* raw */
    const char *ko;
    const char *en;
} mex_enum_t;

typedef enum {
#define ENUM(regkey, value, ...) MEX_ENUM_##regkey##_##value,
#include "mex150/regmap_x.h"
    MEX_ENUM_COUNT
} mex_enum_id_t;

/* Tables (regmap.c). Indexed by the IDs above. */
extern const mex_reg_t mex_regs[MEX_REG_COUNT];
extern const mex_bit_t mex_bits[MEX_BIT_COUNT];
extern const mex_coil_t mex_coils[MEX_COIL_COUNT];
extern const mex_enum_t mex_enums[MEX_ENUM_COUNT];

/** regs[] index of a 4xxxx address. Caller checks the range (40001..40059). */
static inline unsigned mex_reg_index(uint16_t addr) {
    return (unsigned)(addr - MEX_ADDR_BASE);
}

/** REG row for an address, or NULL. O(1) or O(log n). */
const mex_reg_t *mex_reg_find(uint16_t addr);
/** REG row for a key (exact, case-sensitive), or NULL. */
const mex_reg_t *mex_reg_find_key(const char *key);
/** COIL row for coil number n (1..32), or NULL. */
const mex_coil_t *mex_coil_find(uint8_t n);

/** wire -> raw: sign extension for is_signed rows, the unchanged word for every other row. */
int32_t mex_reg_decode(const mex_reg_t *r, uint16_t wire);
/** write request raw -> wire for FC06 (two's complement for signed; RUNBIT rows send 0/1). Caller
 * validates first. */
uint16_t mex_reg_encode(const mex_reg_t *r, int32_t raw);
/**
 * Read-back verification: true iff the register raw read back after a write satisfies the write
 * request raw `requested` (RUNBIT rows: ((read_raw & 0xFF) != 0) == (requested != 0); every other
 * row: read_raw == requested).
 */
bool mex_reg_write_matches(const mex_reg_t *r, int32_t requested, int32_t read_raw);
/** Extract a REGBIT/FIELD value from a wire word. */
uint32_t mex_bit_get(const mex_bit_t *b, uint16_t wire);

/** raw equals the row's disabled sentinel. */
bool mex_reg_is_disabled(const mex_reg_t *r, int32_t raw);

/**
 * Static check of a write request raw (no device state): MEX_R_READONLY if !writable, MEX_R_RANGE
 * if raw is outside min..max and is not the disabled sentinel (RUNBIT rows: only 0/1), else
 * MEX_R_OK. A raw read from live data is NOT necessarily a valid write request (40005 0x0A01).
 */
mex_reason_t mex_reg_check_value(const mex_reg_t *r, int32_t raw);

/**
 * Decimal value -> raw: raw = round(value * scale). Returns false (MEX_R_RANGE semantics) if the
 * value is not finite, not representable at the scale (|value*scale - raw| > 1e-6), or outside
 * int32. Range is NOT checked here.
 */
bool mex_reg_from_value(const mex_reg_t *r, double value, int32_t *raw);

/** Format raw as a decimal string ("23.5", "-0.5", "180"). Returns length or -1 if cap too small. */
int mex_reg_format(const mex_reg_t *r, int32_t raw, char *out, size_t cap);

/** Group wire name: "status","control","setpoint","deviation","delay","calibration","limits",
 * "options","info","alarm". */
const char *mex_group_name(mex_group_t g);

/** Buffer size that always holds a reason wire name ("running_interlock" = 18, "exception:255" = 14). */
#define MEX_REASON_NAME_SZ 24

/**
 * Reason wire name ("range", "exception:2", ...). Copies the name into buf when it fits and returns
 * buf; otherwise returns a static literal (never a truncated name; "exception" for an exception
 * reason). Callers MUST use the return value; pass buf[MEX_REASON_NAME_SZ] to always get a copy.
 */
const char *mex_reason_name(int reason, char *buf, size_t cap);

#ifdef __cplusplus
}
#endif

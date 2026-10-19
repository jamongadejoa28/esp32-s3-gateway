/*
 * regmap_x.h - X-macro expander for ../../regmap.def. Intentionally NO include guard.
 *
 * Usage:
 *     #define REG(key, addr, scale, sign, access, min, max, disabled, flags, group, unit, ko, en) ...
 *     #define COIL(key, n, group, ko, en) ...
 *     #include "mex150/regmap_x.h"
 *
 * Any of REG / REGBIT / FIELD / COIL / ENUM left undefined expands to nothing. (The bit row is
 * REGBIT, not BIT: IDF's esp_bit_defs.h defines BIT(nr), reachable from every FreeRTOS header.) While the
 * table is expanded the column tokens below are macros (so non-pasted arguments arrive as C values: sign ->
 * bool, access -> bool writable, disabled -> int32, flags -> uint32, group -> mex_group_t); pasted arguments
 * (MEX_REG_##key) see the raw token. Afterwards every row macro and token is #undef'd, so nothing leaks into
 * the including file.
 */

#ifndef REG
#define REG(key, addr, scale, sign, access, min, max, disabled, flags, group, unit, ko, en)
#endif
#ifndef REGBIT
#define REGBIT(key, addr, bit, ko, en)
#endif
#ifndef FIELD
#define FIELD(key, addr, lsb, width, unit, ko, en)
#endif
#ifndef COIL
#define COIL(key, n, group, ko, en)
#endif
#ifndef ENUM
#define ENUM(regkey, value, ko, en)
#endif

/* The tokens are #undef'd afterwards: refuse to shadow (and then destroy) a foreign macro. */
#if defined(U) || defined(S) || defined(RO) || defined(RW) || defined(NONE) || defined(STOPPED) ||           \
    defined(SNMP_RW) || defined(RUNBIT) || defined(BITS) || defined(status) || defined(control) ||           \
    defined(setpoint) || defined(deviation) || defined(delay) || defined(calibration) || defined(limits) ||  \
    defined(options) || defined(info) || defined(alarm)
#error "regmap_x.h: a regmap.def column token is already defined as a macro"
#endif

#define U false
#define S true
#define RO false
#define RW true
#define NONE MEX_DIS_NONE
#define STOPPED MEX_F_STOPPED
#define SNMP_RW MEX_F_SNMP_RW
#define RUNBIT MEX_F_RUNBIT
#define BITS MEX_F_BITS
#define status MEX_GRP_STATUS
#define control MEX_GRP_CONTROL
#define setpoint MEX_GRP_SETPOINT
#define deviation MEX_GRP_DEVIATION
#define delay MEX_GRP_DELAY
#define calibration MEX_GRP_CALIBRATION
#define limits MEX_GRP_LIMITS
#define options MEX_GRP_OPTIONS
#define info MEX_GRP_INFO
#define alarm MEX_GRP_ALARM

#include "../../regmap.def"

#undef U
#undef S
#undef RO
#undef RW
#undef NONE
#undef STOPPED
#undef SNMP_RW
#undef RUNBIT
#undef BITS
#undef status
#undef control
#undef setpoint
#undef deviation
#undef delay
#undef calibration
#undef limits
#undef options
#undef info
#undef alarm

#undef REG
#undef REGBIT
#undef FIELD
#undef COIL
#undef ENUM

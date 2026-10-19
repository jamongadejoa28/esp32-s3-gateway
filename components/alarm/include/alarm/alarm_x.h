/*
 * alarm_x.h - X-macro expander for ../../alarm_catalog.def. Intentionally NO include guard.
 * Define ALM(id, code, kind, addr, bit, sev, vreg, ko, en) and include this file; the column
 * tokens (SRC_*, INFO/MINOR/MAJOR/CRITICAL) are macros only during the expansion, and ALM is
 * #undef'd afterwards.
 */
#ifndef ALM
#define ALM(id, code, kind, addr, bit, sev, vreg, ko, en)
#endif

#if defined(SRC_COIL) || defined(SRC_BIT) || defined(SRC_COMM) || defined(SRC_RULE) || defined(INFO) ||      \
    defined(MINOR) || defined(MAJOR) || defined(CRITICAL)
#error "alarm_x.h: an alarm_catalog.def column token is already defined as a macro"
#endif

#define SRC_COIL ALM_SRC_COIL
#define SRC_BIT ALM_SRC_BIT
#define SRC_COMM ALM_SRC_COMM
#define SRC_RULE ALM_SRC_RULE
#define INFO ALM_SEV_INFO
#define MINOR ALM_SEV_MINOR
#define MAJOR ALM_SEV_MAJOR
#define CRITICAL ALM_SEV_CRITICAL

#include "../../alarm_catalog.def"

#undef SRC_COIL
#undef SRC_BIT
#undef SRC_COMM
#undef SRC_RULE
#undef INFO
#undef MINOR
#undef MAJOR
#undef CRITICAL
#undef ALM

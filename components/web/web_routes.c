/* Pure route metadata generated from api_routes.def (web_core.h). The device router uses the
 * handler table built from the same .def in api_routes.c; this table lets host tests check every
 * route's method/role/CSRF/body policy against docs/API.md and exercise the matcher. */
#include <string.h>

#include "web/web_path.h"
#include "web_core.h"

#define M_GET WEB_CORE_M_GET
#define M_POST WEB_CORE_M_POST
#define M_PUT WEB_CORE_M_PUT
#define M_DELETE WEB_CORE_M_DELETE
#define R_NONE GW_ROLE_NONE
#define R_VIEWER GW_ROLE_VIEWER
#define R_OPERATOR GW_ROLE_OPERATOR
#define R_ADMIN GW_ROLE_ADMIN
#define F_0 0u
#define F_CSRF WEB_CORE_RF_CSRF
#define F_MC WEB_CORE_RF_ALLOW_MUST_CHANGE
#define F_RAW WEB_CORE_RF_RAW_BODY
#define F_SLOW WEB_CORE_RF_SLOW
#define F_NOTOUCH WEB_CORE_RF_NO_TOUCH
#define B_NONE 0u
#define B_JSON (8u * 1024u)
#define B_IMPORT (32u * 1024u)
#define B_OTA (3u * 1024u * 1024u)

const web_route_meta_t web_route_meta[] = {
#define ROUTE(m, pat, role, flags, body, h) {m, pat, role, (uint8_t)(flags), body, #h},
#include "api_routes.def"
#undef ROUTE
};

const size_t web_route_meta_count = sizeof(web_route_meta) / sizeof(web_route_meta[0]);

int web_route_meta_find(int method, const char *path, size_t len, bool *method_mismatch) {
    if (method_mismatch) {
        *method_mismatch = false;
    }
    for (size_t i = 0; i < web_route_meta_count; i++) {
        if (web_path_match(web_route_meta[i].pattern, path, len, NULL)) {
            if (web_route_meta[i].method == method) {
                if (method_mismatch) {
                    *method_mismatch = false;
                }
                return (int)i;
            }
            if (method_mismatch) {
                *method_mismatch = true;
            }
        }
    }
    return -1;
}

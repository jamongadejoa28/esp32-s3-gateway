/* Device route table generated from api_routes.def (handlers in api_*.c). */
#include "web_priv.h"

#define M_GET HTTP_GET
#define M_POST HTTP_POST
#define M_PUT HTTP_PUT
#define M_DELETE HTTP_DELETE
#define R_NONE GW_ROLE_NONE
#define R_VIEWER GW_ROLE_VIEWER
#define R_OPERATOR GW_ROLE_OPERATOR
#define R_ADMIN GW_ROLE_ADMIN
#define F_0 0u
#define F_CSRF WEB_RF_CSRF
#define F_MC WEB_RF_ALLOW_MUST_CHANGE
#define F_RAW WEB_RF_RAW_BODY
#define F_SLOW WEB_RF_SLOW
#define F_NOTOUCH WEB_RF_NO_TOUCH
#define B_NONE 0u
#define B_JSON WEB_BODY_JSON_MAX
#define B_IMPORT WEB_BODY_IMPORT_MAX
#define B_OTA WEB_BODY_OTA_MAX

const web_route_t web_api_routes[] = {
#define ROUTE(m, pat, role, flags, body, h) {m, pat, role, (uint8_t)(flags), body, h},
#include "api_routes.def"
#undef ROUTE
};

const size_t web_api_routes_count = sizeof(web_api_routes) / sizeof(web_api_routes[0]);

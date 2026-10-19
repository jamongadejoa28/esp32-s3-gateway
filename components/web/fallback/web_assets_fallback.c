/* Empty static-UI table for builds without the generated web_assets.c (no node / web sources).
 * Selected by cmake/gw_web_assets.cmake; contract: web/web_assets.h. Not in SRC_DIRS on purpose. */
#include "web/web_assets.h"

const web_asset_t gw_web_assets[] = {{NULL, NULL, NULL, NULL, 0, false}};
const size_t gw_web_assets_count = 0;

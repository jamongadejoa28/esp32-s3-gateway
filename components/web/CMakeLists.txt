# Sources are globbed: run 'idf.py reconfigure' after adding/removing a .c file.
idf_component_register(
  SRC_DIRS "."
  INCLUDE_DIRS "include"
  REQUIRES gw_core auth esp_http_server
  PRIV_REQUIRES store mex150 alarm net sysmgr snmp_gw cjson mbedtls app_update esp_app_format esp_partition espcoredump esp_timer lwip
)
target_compile_options(${COMPONENT_LIB} PRIVATE
  -Wall -Wextra -Werror=implicit-function-declaration -Wframe-larger-than=2048)

# Static UI table (generated web_assets.c or the empty fallback); see cmake/gw_web_assets.cmake.
include("${CMAKE_CURRENT_LIST_DIR}/../../cmake/gw_web_assets.cmake")
gw_web_assets(${COMPONENT_LIB})

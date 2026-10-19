# Sources are globbed: run 'idf.py reconfigure' after adding/removing a .c file.
# snmp_logic.c is also host-built (cmake/gw_host_sources.cmake, tests/test_snmp_logic.py).
idf_component_register(
  SRC_DIRS "."
  INCLUDE_DIRS "include"
  REQUIRES gw_core snmp_lwip
  PRIV_REQUIRES mex150 store alarm net lwip nvs_flash esp_timer esp_app_format esp_hw_support
)
target_compile_options(${COMPONENT_LIB} PRIVATE
  -Wall -Wextra -Wunused-parameter -Wsign-compare -Werror=implicit-function-declaration
  -Wframe-larger-than=2048)

# Generated MESTIO-GW-MIB, embedded gzip (snmp_gw_mib_gz()); see cmake/gw_mib.cmake.
include("${CMAKE_CURRENT_LIST_DIR}/../../cmake/gw_mib.cmake")
gw_mib(${COMPONENT_LIB})

# Keep the agent in the image even before main/app_main.c calls snmp_gw_start() (Phase 2), so the
# link proves that the agent, its MIB modules and the lwIP SNMP core resolve (tests/test_link_check.py).
target_link_libraries(${COMPONENT_LIB} INTERFACE "-u snmp_gw_start")

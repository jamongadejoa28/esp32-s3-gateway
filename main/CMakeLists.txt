# contract_check.c compiles every frozen public header with the IDF toolchain (no code generated).
idf_component_register(
  SRCS "app_main.c" "contract_check.c"
  PRIV_REQUIRES nvs_flash app_update esp_timer esp_netif esp_app_format esp_hal_gpspi esp_hal_uart lwip
                gw_core board net mex150 store alarm auth web snmp_lwip snmp_gw sysmgr)
target_compile_options(${COMPONENT_LIB} PRIVATE
  -Wall -Wextra -Werror=implicit-function-declaration -Wframe-larger-than=2048)

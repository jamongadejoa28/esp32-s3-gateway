# Sources are globbed: run 'idf.py reconfigure' after adding/removing a .c file.
idf_component_register(
  SRC_DIRS "."
  INCLUDE_DIRS "include"
  PRIV_INCLUDE_DIRS "."
  REQUIRES gw_core store
  PRIV_REQUIRES board esp_netif esp_eth esp_event esp_wifi esp_driver_spi esp_driver_gpio esp_hw_support lwip w5500
)
target_compile_options(${COMPONENT_LIB} PRIVATE
  -Wall -Wextra -Werror=implicit-function-declaration -Wframe-larger-than=2048)

# Strong-host rule for the recovery AP (DESIGN.md §6, DECISIONS.md FIXER/F): inject
# lwip_hooks/net_lwip_hooks.h into lwIP's own translation units as ESP_IDF_LWIP_HOOK_FILENAME
# (IDF 6.1 lwip_default_hooks.h; docs/api-guides/lwip.rst "Customized lwIP Hooks"). The hook is a
# static inline, so lwip needs no link dependency on this component.
idf_component_get_property(net_lwip_lib lwip COMPONENT_LIB)
target_compile_definitions(${net_lwip_lib} PRIVATE
  "ESP_IDF_LWIP_HOOK_FILENAME=\"${CMAKE_CURRENT_LIST_DIR}/lwip_hooks/net_lwip_hooks.h\"")

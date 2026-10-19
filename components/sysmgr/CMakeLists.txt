# Sources are globbed: run 'idf.py reconfigure' after adding/removing a .c file.
idf_component_register(
  SRC_DIRS "."
  INCLUDE_DIRS "include"
  REQUIRES gw_core
  PRIV_REQUIRES board net store alarm mex150 app_update esp_app_format bootloader_support esp_partition espcoredump
                console nvs_flash esp_system esp_timer esp_netif lwip esp_driver_usb_serial_jtag
)
target_compile_options(${COMPONENT_LIB} PRIVATE
  -Wall -Wextra -Werror=implicit-function-declaration -Wframe-larger-than=2048)

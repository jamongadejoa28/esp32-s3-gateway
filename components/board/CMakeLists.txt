# Sources are globbed: run 'idf.py reconfigure' after adding/removing a .c file.
idf_component_register(
  SRC_DIRS "."
  INCLUDE_DIRS "include"
  REQUIRES gw_core
  PRIV_REQUIRES esp_driver_gpio esp_driver_i2c led_strip esp_timer
)
target_compile_options(${COMPONENT_LIB} PRIVATE
  -Wall -Wextra -Werror=implicit-function-declaration -Wframe-larger-than=2048)

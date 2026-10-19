# Sources are globbed: run 'idf.py reconfigure' after adding/removing a .c file.
idf_component_register(
  SRC_DIRS "."
  INCLUDE_DIRS "include"
  REQUIRES gw_core mex150 store
  PRIV_REQUIRES esp_timer
)
target_compile_options(${COMPONENT_LIB} PRIVATE
  -Wall -Wextra -Werror=implicit-function-declaration -Wframe-larger-than=2048)

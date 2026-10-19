# Sources are globbed: run 'idf.py reconfigure' after adding/removing a .c file.
# Host-test-only sources are excluded from the firmware image.
idf_component_register(
  SRC_DIRS "."
  EXCLUDE_SRCS "crypto_openssl.c"
  INCLUDE_DIRS "include"
  REQUIRES esp_event
  PRIV_REQUIRES esp_timer mbedtls bootloader_support esp_hw_support
)
target_compile_options(${COMPONENT_LIB} PRIVATE
  -Wall -Wextra -Werror=implicit-function-declaration -Wframe-larger-than=2048)

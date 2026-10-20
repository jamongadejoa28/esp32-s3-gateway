cmake_minimum_required(VERSION 3.22)

# Single version source: version.txt -> esp_app_desc.version, UI, sysDescr.
file(STRINGS "${CMAKE_CURRENT_LIST_DIR}/version.txt" PROJECT_VER LIMIT_COUNT 1)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

if(NOT IDF_VERSION_MAJOR EQUAL 6 OR NOT IDF_VERSION_MINOR EQUAL 1)
  message(FATAL_ERROR "Use ESP-IDF v6.1 (VS Code: ESP-IDF Select Current ESP-IDF Version); "
                      "found ${IDF_VERSION_MAJOR}.${IDF_VERSION_MINOR}.${IDF_VERSION_PATCH}")
endif()

# lwIP SNMP agent options. Project-wide because lwIP SNMP struct layouts depend on them
# (every TU including lwip/apps/snmp*.h must agree). Validated against IDF 6.1
# lwip/src/include/lwip/apps/snmp_opts.h; see docs/DECISIONS.md (SCAFFOLD).
# SNMP_USE_NETCONN=1 only satisfies snmp_opts.h's "needs a receive API" check; upstream
# snmp_netconn.c is not compiled (components/snmp_lwip/snmp_transport.c replaces it).
foreach(d LWIP_SNMP=1 SNMP_USE_NETCONN=1 SNMP_USE_RAW=0 LWIP_SNMP_V3=1 LWIP_SNMP_V3_MBEDTLS=0
          LWIP_SNMP_V3_CRYPTO=1 LWIP_SNMP_CONFIGURE_VERSIONS=1 SNMP_LWIP_MIB2=0
          SNMP_TRAP_DESTINATIONS=1 SNMP_MAX_COMMUNITY_STR_LEN=32 SNMP_MAX_OBJ_ID_LEN=50
          SNMP_LWIP_GETBULK_MAX_REPETITIONS=16)
  idf_build_set_property(COMPILE_DEFINITIONS "${d}" APPEND)
endforeach()

project(mestio_gw)
gw_web_images()

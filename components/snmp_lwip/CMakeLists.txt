# Upstream lwIP SNMP agent subset (IDF's lwip component does not build apps/snmp) plus our
# PSA-Crypto SNMPv3 backend and single-thread netconn transport. Option macros (LWIP_SNMP=1, ...)
# are project-wide COMPILE_DEFINITIONS set in the top-level CMakeLists.txt.
idf_build_get_property(idf_path IDF_PATH)
set(upstream_dir "${idf_path}/components/lwip/lwip/src/apps/snmp")

# Excluded on purpose: snmp_netconn.c / snmp_raw.c (replaced by snmp_transport.c),
# snmpv3_mbedtls.c (private mbedTLS 4 APIs, DES), snmp_mib2*.c, snmp_threadsync.c.
set(upstream_srcs
  "${upstream_dir}/snmp_asn1.c"
  "${upstream_dir}/snmp_core.c"
  "${upstream_dir}/snmp_msg.c"
  "${upstream_dir}/snmp_pbuf_stream.c"
  "${upstream_dir}/snmp_scalar.c"
  "${upstream_dir}/snmp_table.c"
  "${upstream_dir}/snmpv3.c"
  "${upstream_dir}/snmp_snmpv2_framework.c"
  "${upstream_dir}/snmp_snmpv2_usm.c")
set(own_srcs "snmpv3_psa.c" "snmp_transport.c" "snmpv3_selftest.c")

# snmp_traps.c is compiled from a fixed copy (v2c sysUpTime.0 / snmpTrapOID.0 instance arcs, see
# snmp_traps_fix.cmake), regenerated at configure time when upstream or the fix script changes.
# (Not during IDF's early requirement expansion, which runs this file in script mode.)
set(SNMP_TRAPS_IN "${upstream_dir}/snmp_traps.c")
set(SNMP_TRAPS_OUT "${CMAKE_CURRENT_BINARY_DIR}/snmp_traps_fixed.c")
if(NOT CMAKE_BUILD_EARLY_EXPANSION)
  include("${CMAKE_CURRENT_LIST_DIR}/snmp_traps_fix.cmake")
  set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    "${SNMP_TRAPS_IN}" "${CMAKE_CURRENT_LIST_DIR}/snmp_traps_fix.cmake")
endif()
list(APPEND upstream_srcs "${SNMP_TRAPS_OUT}")

idf_component_register(
  SRCS ${own_srcs}
  INCLUDE_DIRS "include"
  REQUIRES lwip
  PRIV_REQUIRES gw_core mbedtls esp_netif esp_timer)

# Upstream files live inside the lwip component dir; adding them to the target directly (not via
# SRCS/PRIV_INCLUDE_DIRS) avoids IDF's cross-component ownership warnings.
target_sources(${COMPONENT_LIB} PRIVATE ${upstream_srcs})
target_include_directories(${COMPONENT_LIB} PRIVATE "${upstream_dir}")

# Our sources get the project warning set; upstream sources keep IDF defaults.
set_source_files_properties(${own_srcs} PROPERTIES COMPILE_OPTIONS
  "-Wall;-Wextra;-Wunused-parameter;-Wsign-compare;-Werror=implicit-function-declaration;-Wframe-larger-than=2048")
# lwIP defines MIB2_COPY_SYSUPTIME_TO only with MIB2_STATS (off in IDF); without this override every
# trap carries sysUpTime 0. snmp_lwip_port.h supplies the agent's uptime (see that header).
set_source_files_properties("${SNMP_TRAPS_OUT}" PROPERTIES COMPILE_OPTIONS
  "-include;${CMAKE_CURRENT_LIST_DIR}/snmp_lwip_port.h")

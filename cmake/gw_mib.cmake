# MESTIO-GW-MIB build hook. Owner: stream E. Contract: snmp_gw_mib_gz() in
# components/snmp_gw/include/snmp_gw/snmp_gw.h. Included from components/snmp_gw/CMakeLists.txt after
# idf_component_register():
#   gw_mib(${COMPONENT_LIB})
# generates ${CMAKE_CURRENT_BINARY_DIR}/MESTIO-GW-MIB.txt.gz with tools/gen_mib.py (gzip -9, mtime 0,
# deterministic) from regmap.def, alarm_catalog.def and CONFIG_GW_SNMP_ENTERPRISE_PEN, rebuilt whenever
# one of them or the generator changes (a PEN change alters the command line, which also reruns it),
# and embeds it with target_add_binary_data(... BINARY) as _binary_MESTIO_GW_MIB_txt_gz_start/_end.
# A generator failure fails the build: the firmware never ships without its MIB.

function(gw_mib target)
  get_filename_component(gw_root "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/.." ABSOLUTE)
  idf_build_get_property(python PYTHON)
  if(NOT DEFINED CONFIG_GW_SNMP_ENTERPRISE_PEN OR "${CONFIG_GW_SNMP_ENTERPRISE_PEN}" STREQUAL "")
    message(FATAL_ERROR "gw_mib: CONFIG_GW_SNMP_ENTERPRISE_PEN is not set (main/Kconfig.projbuild)")
  endif()
  set(regmap "${gw_root}/components/mex150/regmap.def")
  set(catalog "${gw_root}/components/alarm/alarm_catalog.def")
  set(gen "${gw_root}/tools/gen_mib.py")
  set(out "${CMAKE_CURRENT_BINARY_DIR}/MESTIO-GW-MIB.txt.gz")
  add_custom_command(
    OUTPUT "${out}"
    COMMAND "${python}" "${gen}" --regmap "${regmap}" --catalog "${catalog}"
            --pen "${CONFIG_GW_SNMP_ENTERPRISE_PEN}" --out "${out}"
    DEPENDS "${regmap}" "${catalog}" "${gen}"
    WORKING_DIRECTORY "${gw_root}"
    COMMENT "Generating MESTIO-GW-MIB (enterprise ${CONFIG_GW_SNMP_ENTERPRISE_PEN})"
    VERBATIM)
  set_property(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}" APPEND PROPERTY ADDITIONAL_CLEAN_FILES "${out}")
  target_add_binary_data(${target} "${out}" BINARY)
endfunction()

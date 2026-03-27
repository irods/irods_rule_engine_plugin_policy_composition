set(TARGET_NAME "irods_rule_engine_plugin-event_handler-zone_modified")
string(REPLACE "_" "-" TARGET_NAME_HYPHENS ${TARGET_NAME})

set(
  IRODS_PLUGIN_POLICY_COMPILE_DEFINITIONS
  RODS_SERVER
  ENABLE_RE
  )

set(
  IRODS_PLUGIN_POLICY_LINK_LIBRARIES
  irods_server
  )

add_library(
    ${TARGET_NAME}
    MODULE
    ${CMAKE_SOURCE_DIR}/lib${TARGET_NAME}.cpp
    )

target_include_directories(
    ${TARGET_NAME}
    PRIVATE
    ${IRODS_INCLUDE_DIRS}
    ${IRODS_EXTERNALS_FULLPATH_BOOST}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    )

target_link_libraries(
    ${TARGET_NAME}
    PRIVATE
    ${IRODS_PLUGIN_POLICY_LINK_LIBRARIES}
    irods_common
    irods_dev_policy_composition_framework
    nlohmann_json::nlohmann_json
    fmt::fmt
    ${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_regex.so
    )

target_compile_definitions(${TARGET_NAME} PRIVATE ${IRODS_PLUGIN_POLICY_COMPILE_DEFINITIONS} ${IRODS_COMPILE_DEFINITIONS} BOOST_SYSTEM_NO_DEPRECATED)
target_compile_options(${TARGET_NAME} PRIVATE -Wno-write-strings)

install(
  TARGETS
  ${TARGET_NAME}
  LIBRARY
  DESTINATION ${IRODS_PLUGINS_DIRECTORY}/rule_engines
  )

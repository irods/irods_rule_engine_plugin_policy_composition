cmake_minimum_required(VERSION 3.14...3.18 FATAL_ERROR) #CPACK_DEBIAN_<COMPONENT>_PACKAGE_NAME

set(IRODS_MINIMUM_VERSION "4.90.0")
set(IRODS_MAXIMUM_VERSION "6.0.0")
find_package(IRODS "${IRODS_MINIMUM_VERSION}...<${IRODS_MAXIMUM_VERSION}" REQUIRED)

set(IRODS_PLUGIN_VERSION "0.1.0")
set(IRODS_PACKAGE_REVISION "0")

include(RequireOutOfSourceBuild)
include(IrodsCXXCompiler)

set(CMAKE_CXX_STANDARD ${IRODS_CXX_STANDARD})

set(CMAKE_EXE_LINKER_FLAGS_INIT "-Wl,--export-dynamic -Wl,--enable-new-dtags -Wl,--as-needed")
set(CMAKE_MODULE_LINKER_FLAGS_INIT "-Wl,--enable-new-dtags -Wl,--as-needed")
set(CMAKE_SHARED_LINKER_FLAGS_INIT "-Wl,--enable-new-dtags -Wl,--as-needed")
set(CMAKE_EXE_LINKER_FLAGS_RELEASE_INIT "-Wl,--gc-sections -Wl,-z,combreloc")
set(CMAKE_MODULE_LINKER_FLAGS_RELEASE_INIT "-Wl,--gc-sections -Wl,-z,combreloc")
set(CMAKE_SHARED_LINKER_FLAGS_RELEASE_INIT "-Wl,--gc-sections -Wl,-z,combreloc")

if (IRODS_ENABLE_ADDRESS_SANITIZER)
  # The following options are compiled into all binaries and allow them to start even
  # when an ODR violation is detected.
  #
  # Make sure the correct llvm-symbolizer binary is available to Address Sanitizer. This binary
  # allows debug symbols to be reported appropriately. There are two ways to do this:
  #
  #     export PATH=/opt/irods-externals/clang13.0.0-0/bin:$PATH
  #
  # - or -
  #
  #     export ASAN_SYMBOLIZER_PATH=/opt/irods-externals/clang13.0.0-0/bin/llvm-symbolizer
  #
  add_compile_options(-fsanitize=address)
  add_link_options(-fsanitize=address)
endif()

if (IRODS_ENABLE_UNDEFINED_BEHAVIOR_SANITIZER)
  # Make sure the correct llvm-symbolizer binary is available to Undefined Behavior Sanitizer. This binary
  # allows debug symbols to be reported appropriately. Additionally, set options for logging.
  #
  #     export PATH=/opt/irods-externals/clang13.0.1-0/bin:$PATH
  add_compile_options(
    -fsanitize=undefined
    -fsanitize=float-divide-by-zero
    -fsanitize=unsigned-integer-overflow
    -fsanitize=local-bounds
    -fsanitize=nullability)
  add_link_options(
    -fsanitize=undefined
    -fsanitize=float-divide-by-zero
    -fsanitize=unsigned-integer-overflow
    -fsanitize=local-bounds
    -fsanitize=nullability)

  if (IRODS_ENABLE_UNDEFINED_BEHAVIOR_SANITIZER_IMPLICIT_CONVERSION_CHECK)
     add_compile_options(-fsanitize=implicit-conversion)
     add_link_options(-fsanitize=implicit-conversion)
  endif()
endif()

if (IRODS_ENABLE_ADDRESS_SANITIZER OR IRODS_ENABLE_UNDEFINED_BEHAVIOR_SANITIZER)
  add_compile_options(
    -fno-omit-frame-pointer
    -fno-optimize-sibling-calls
    -O1)
  add_link_options(
    -fno-omit-frame-pointer
    -fno-optimize-sibling-calls
    -O1)
else()
  set(CMAKE_EXE_LINKER_FLAGS_INIT "${CMAKE_EXE_LINKER_FLAGS_INIT} -Wl,-z,defs")
  set(CMAKE_MODULE_LINKER_FLAGS_INIT "${CMAKE_MODULE_LINKER_FLAGS_INIT} -Wl,-z,defs")
  set(CMAKE_SHARED_LINKER_FLAGS_INIT "${CMAKE_SHARED_LINKER_FLAGS_INIT} -Wl,-z,defs")
endif()

set(PROJECT_NAME irods_rule_engine_plugin_policy_composition)
string(REPLACE "_" "-" PROJECT_NAME_HYPHENS ${PROJECT_NAME})

project(${PROJECT_NAME}
  VERSION "${IRODS_PLUGIN_VERSION}"
  LANGUAGES CXX)

include(${IRODS_TARGETS_PATH})
include(GNUInstallDirs)
include(IrodsRunpathDefaults)

if (NOT CPACK_PACKAGING_INSTALL_PREFIX)
  set(CPACK_PACKAGING_INSTALL_PREFIX "/" CACHE STRING "Package root path. \"/\" is correct for normal package builds.." FORCE)
  message(STATUS "Setting unspecified CPACK_PACKAGING_INSTALL_PREFIX to '${CPACK_PACKAGING_INSTALL_PREFIX}'. This is the correct setting for normal builds.")
endif()


if (NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build {Debug, Release}." FORCE)
  message(STATUS "Setting unspecified CMAKE_BUILD_TYPE to '${CMAKE_BUILD_TYPE}'")
endif()

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED COMPONENTS Crypto SSL)
find_package(nlohmann_json "3.6.1" REQUIRED)

find_package(fmt 8.1.1 REQUIRED)

include(IrodsCPackCommon)

list(APPEND CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION "${CPACK_PACKAGING_INSTALL_PREFIX}${IRODS_HOME_DIRECTORY}")
list(APPEND CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION "${CPACK_PACKAGING_INSTALL_PREFIX}${IRODS_HOME_DIRECTORY}/scripts")
list(APPEND CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION "${CPACK_PACKAGING_INSTALL_PREFIX}${IRODS_HOME_DIRECTORY}/scripts/irods")
list(APPEND CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION "${CPACK_PACKAGING_INSTALL_PREFIX}${IRODS_HOME_DIRECTORY}/scripts/irods/test")

set(CPACK_INCLUDE_TOPLEVEL_DIRECTORY OFF)
set(CPACK_COMPONENT_INCLUDE_TOPLEVEL_DIRECTORY OFF)
set(CPACK_COMPONENTS_GROUPING IGNORE)

set(CPACK_DEB_COMPONENT_INSTALL OFF)
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS OFF)
set(CPACK_DEBIAN_PACKAGE_CONTROL_STRICT_PERMISSION ON)
set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA "${CMAKE_SOURCE_DIR}/packaging/postinst;")
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)

set(CPACK_RPM_COMPONENT_INSTALL OFF)
set(CPACK_RPM_PACKAGE_LICENSE "BSD-3-Clause")
set(CPACK_RPM_POST_INSTALL_SCRIPT_FILE "${CMAKE_SOURCE_DIR}/packaging/postinst")
set(CPACK_RPM_PACKAGE_AUTOREQ 0)
set(CPACK_RPM_PACKAGE_AUTOPROV 0)
set(CPACK_RPM_FILE_NAME RPM-DEFAULT)

set(CPACK_ARCHIVE_COMPONENT_INSTALL OFF)

add_subdirectory(framework)

set(CPACK_DEBIAN_PACKAGE_NAME ${PROJECT_NAME_HYPHENS})
set(CPACK_DEBIAN_POLICY_PACKAGE_DEPENDS "${IRODS_PACKAGE_DEPENDENCIES_STRING}, irods-server (= ${IRODS_VERSION}), irods-runtime (= ${IRODS_VERSION}), libc6")

set(CPACK_RPM_PACKAGE_NAME ${PROJECT_NAME_HYPHENS})
set(CPACK_RPM_POLICY_PACKAGE_REQUIRES "${IRODS_PACKAGE_DEPENDENCIES_STRING}, irods-server = ${IRODS_VERSION}, irods-runtime = ${IRODS_VERSION}")

# include all cmake files for rule engine plugins for this repository

include(${CMAKE_SOURCE_DIR}/data_replication.cmake)
include(${CMAKE_SOURCE_DIR}/data_retention.cmake)
include(${CMAKE_SOURCE_DIR}/data_verification.cmake)
include(${CMAKE_SOURCE_DIR}/filesystem_usage.cmake)
include(${CMAKE_SOURCE_DIR}/log_context.cmake)
include(${CMAKE_SOURCE_DIR}/query_processor.cmake)

if (BUILD_TESTING_POLICY OR (CMAKE_BUILD_TYPE STREQUAL "Debug"))
    include(${CMAKE_SOURCE_DIR}/testing_policy.cmake)
endif()

include(${CMAKE_SOURCE_DIR}/event_handler_data_object_modified.cmake)
include(${CMAKE_SOURCE_DIR}/event_handler_metadata_modified.cmake)
include(${CMAKE_SOURCE_DIR}/event_handler_collection_modified.cmake)
include(${CMAKE_SOURCE_DIR}/event_handler_user_modified.cmake)
include(${CMAKE_SOURCE_DIR}/event_handler_resource_modified.cmake)
include(${CMAKE_SOURCE_DIR}/verify_checksum.cmake)

install(
    FILES
    packaging/test_plugins_policy.py
    DESTINATION var/lib/irods/scripts/irods/test
    COMPONENT testing)

if (NOT CPACK_GENERATOR)
    set(CPACK_GENERATOR ${IRODS_CPACK_GENERATOR} CACHE STRING "CPack generator to use, e.g. {DEB, RPM, TGZ}." FORCE)
    message(STATUS "Setting unspecified CPACK_GENERATOR to ${CPACK_GENERATOR}. This is the correct setting for normal builds.")
endif()

include(CPack)

cmake_minimum_required(VERSION 3.0 FATAL_ERROR)

project(ZeekPluginNdpi)

include(ZeekPlugin)

zeek_plugin_begin(Zeek Ndpi)
zeek_plugin_cc(src/Plugin.cc)
zeek_plugin_cc(src/NdpiDumper.cc)
zeek_plugin_cc(src/ndpi-util/ndpiReader.c)
zeek_plugin_cc(src/ndpi-util/ndpi_util.c)
zeek_plugin_link_library(-lpcap)
zeek_plugin_link_library(-lpthread)
zeek_plugin_link_library(-lndpi)
zeek_plugin_end()

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" VERSION LIMIT_COUNT 1)

if ("${PROJECT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")
    # Allows building rpm/deb packages via "make package" in build dir.
    include(ConfigurePackaging)
    ConfigurePackaging(${VERSION})
endif ()

cmake_minimum_required(VERSION 3.27)
project(ida-chat)

# --- IDA SDK setup via official ida-cmake ---
# IDASDK env var must point to the SDK root (the directory containing src/)
# For the GitHub clone layout, it should point to the repo/src directory.
if(NOT DEFINED ENV{IDASDK})
    # Auto-detect: look for ../idasdk/src/include/ida.hpp relative to this project
    get_filename_component(_PARENT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/.." ABSOLUTE)
    if(EXISTS "${_PARENT_DIR}/idasdk/src/include/ida.hpp")
        set(ENV{IDASDK} "${_PARENT_DIR}/idasdk/src")
        message(STATUS "Auto-detected IDASDK at: $ENV{IDASDK}")
    else()
        message(FATAL_ERROR
            "IDASDK environment variable not set.\n"
            "Set it to the IDA SDK src/ directory, e.g.:\n"
            "  export IDASDK=/path/to/idasdk/src\n"
            "  cmake -B build")
    endif()
endif()

include($ENV{IDASDK}/cmake/bootstrap.cmake)
find_package(idasdk REQUIRED)

# --- libcurl ---
find_package(CURL REQUIRED)

# --- nlohmann/json (header-only) ---
add_library(nlohmann_json INTERFACE)
target_include_directories(nlohmann_json INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/third_party)

# --- Create the Qt plugin ---
ida_add_plugin(ida-chat
    TYPE QT
    QT_COMPONENTS Core Widgets
    SOURCES
        src/plugin.cpp
        src/plugin.h
        src/config.cpp
        src/config.h
        src/api_client.cpp
        src/api_client.h
        src/tool_definitions.cpp
        src/tool_definitions.h
        src/tool_executor.cpp
        src/tool_executor.h
        src/worker_thread.cpp
        src/worker_thread.h
        src/chat_widget.cpp
        src/chat_widget.h
    LIBRARIES
        nlohmann_json
        CURL::libcurl
    INCLUDES
        ${CMAKE_CURRENT_SOURCE_DIR}/src
    DEFINES
        QT_NAMESPACE=QT
        QT_CORE_LIB
        QT_WIDGETS_LIB
)

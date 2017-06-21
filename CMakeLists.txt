# cmake -DCMAKE_TOOLCHAIN_FILE=~/bfprefix/cmake/CMakeToolchain_VMM.txt ..

cmake_minimum_required(VERSION 3.6)
project(eapis C CXX)

if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    if(NOT WIN32 STREQUAL "1")
        set(CMAKE_INSTALL_PREFIX $ENV{HOME}/bfprefix CACHE PATH "" FORCE)
    else()
        set(CMAKE_INSTALL_PREFIX $ENV{HOMEPATH}/bfprefix CACHE PATH "" FORCE)
    endif()
endif()

include(${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Project.txt)

# ------------------------------------------------------------------------------
# Subdirectories
# ------------------------------------------------------------------------------

add_subdirectory(src)

if(ENABLE_UNITTESTING AND NOT CMAKE_TOOLCHAIN_FILE)
    add_subdirectory(tests)
endif()

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

install(DIRECTORY include/exit_handler DESTINATION include)
install(DIRECTORY include/vmcs DESTINATION include)
install(FILES include/bitmanip_eapis.h DESTINATION include)

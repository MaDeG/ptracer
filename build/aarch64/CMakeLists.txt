cmake_minimum_required(VERSION 3.22)
project(ptracer VERSION 0.1.0
        DESCRIPTION "Library and utility tool that can inspect all the system calls performed by a process together with their stack traces"
        HOMEPAGE_URL "https://github.com/MaDeG/ptracer"
        LANGUAGES CXX)

include(GNUInstallDirs)

set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_BUILD_TYPE Debug)

if(NOT EXISTS "${CMAKE_BINARY_DIR}/conan.cmake")
    message(STATUS "Downloading conan.cmake from https://github.com/conan-io/cmake-conan")
    file(DOWNLOAD "https://raw.githubusercontent.com/conan-io/cmake-conan/0.18.1/conan.cmake"
            "${CMAKE_BINARY_DIR}/conan.cmake"
            TLS_VERIFY ON)
endif()
include(${CMAKE_BINARY_DIR}/conan.cmake)

conan_cmake_autodetect(settings)
conan_cmake_configure(REQUIRES boost/1.80.0
                      GENERATORS cmake_find_package
                                 virtualenv
                      OPTIONS boost:shared=False
                              boost:without_atomic=False
                              boost:without_chrono=False
                              boost:without_container=False
                              boost:without_context=True
                              boost:without_contract=True
                              boost:without_coroutine=True
                              boost:without_date_time=False
                              boost:without_exception=False
                              boost:without_fiber=True
                              boost:without_filesystem=False
                              boost:without_graph=True
                              boost:without_graph_parallel=True
                              boost:without_iostreams=True
                              boost:without_json=True
                              boost:without_locale=True
                              boost:without_log=False
                              boost:without_math=True
                              boost:without_mpi=True
                              boost:without_nowide=True
                              boost:without_program_options=False
                              boost:without_python=True
                              boost:without_random=False
                              boost:without_regex=False
                              boost:without_serialization=True
                              boost:without_stacktrace=True
                              boost:without_system=False
                              boost:without_test=True
                              boost:without_thread=False
                              boost:without_timer=True
                              boost:without_type_erasure=True
                              boost:without_wave=True)
# Set conan environment variables generated using the virtualenv generator
# This is necessary since for some reason Conan does not correctly set the variables found (e.g. the Android NDK compiler path)
 if(EXISTS "${CMAKE_BINARY_DIR}/environment.sh.env")
     FILE(READ "${CMAKE_BINARY_DIR}/environment.sh.env" _contents)
     STRING(REGEX REPLACE "\n" ";" _contents "${_contents}")
     foreach(_line ${_contents})
         string(REGEX MATCH "([^=]+)=\"(.*)\"" _match ${_line})
         if(NOT "${_match}" STREQUAL "")
             # message("in ${CMAKE_MATCH_1} = ${CMAKE_MATCH_2}")
             set(ENV{${CMAKE_MATCH_1}} "${CMAKE_MATCH_2}")
         endif()
     endforeach()
     unset(_contents)
     unset(_line)
     unset(_match)
 endif()
conan_cmake_install(PATH_OR_REFERENCE .
                    PROFILE_HOST ../armv8.profile
                    BUILD missing
                    SETTINGS_BUILD ${settings})

set(CMAKE_C_COMPILER   $ENV{CC})
set(CMAKE_CXX_COMPILER $ENV{CXX})
set(CMAKE_AR           $ENV{AR})
set(CMAKE_RANLIB       $ENV{RANLIB})
set(CMAKE_STRIP        $ENV{STRIP})

SET(Boost_DEBUG TRUE)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_BINARY_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -c -Werror -Wall -Wextra -MMD -Wall -Wextra -Wconversion -Wsign-conversion")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fexceptions -fstack-protector-all -Wstack-protector -ftrapv -Wno-unused-but-set-variable -Wformat -Wformat-security -D_FORTIFY_SOURCE=2 -U_FORTIFY_SOURCE -fvisibility=hidden")
add_compile_options(-fexceptions -frtti)

# Needed for the usage of the correct data structures to extract process information via ptrace
add_compile_definitions(ARCH_ARM)

find_package(Boost 1.40 COMPONENTS program_options log REQUIRED)
#find_package(libunwind REQUIRED)
#set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${LIBUNWIND_LIBRARIES}")
#find_package(Threads REQUIRED)

file(GLOB SRC CONFIGURE_DEPENDS "../../src/*.h" "../../src/*.cpp")
message("Source files: ${SRC}")

add_library(prtracer-objects OBJECT ${SRC})
# shared libraries need PIC
set_property(TARGET prtracer-objects PROPERTY POSITION_INDEPENDENT_CODE 1)

add_executable(ptracer $<TARGET_OBJECTS:prtracer-objects>)
# Build shared library
add_library(ptracer-shared SHARED $<TARGET_OBJECTS:prtracer-objects>)
set_target_properties(ptracer-shared PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(ptracer-shared PROPERTIES PUBLIC_HEADER ../../src/TracingManager.h)
install(TARGETS ptracer-shared
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
# Build static library
add_library(ptracer-static STATIC $<TARGET_OBJECTS:prtracer-objects>)
set_target_properties(ptracer-static PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(ptracer-static PROPERTIES PUBLIC_HEADER ../../src/TracingManager.h)
install(TARGETS ptracer-static
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

target_link_libraries(ptracer PRIVATE Boost::program_options Boost::thread)

include_directories(${CMAKE_SYSROOT}/usr/include/c++/v1/ ${CMAKE_SYSROOT}/usr/include/aarch64-linux-android/ ${Boost_INCLUDES})

# get_cmake_property(_variableNames VARIABLES)
# list (SORT _variableNames)
# foreach (_variableName ${_variableNames})
#     message(STATUS "${_variableName}=${${_variableName}}")
# endforeach()
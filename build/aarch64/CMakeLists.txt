if (POLICY CMP0048)
    cmake_policy(SET CMP0048 NEW)
endif (POLICY CMP0048)

project(ConanWrapper
        VERSION 1.0.0
        LANGUAGES C)

cmake_minimum_required(VERSION 3.22)

set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_BUILD_TYPE Debug)

# Require out-of-source builds
file(TO_CMAKE_PATH "${PROJECT_BINARY_DIR}/CMakeLists.txt" LOC_PATH)
if(EXISTS "${LOC_PATH}")
    message(FATAL_ERROR "You cannot build in a source directory (or any directory with a CMakeLists.txt file). Please make a build subdirectory. Feel free to remove CMakeCache.txt and CMakeFiles.")
endif()

if(NOT EXISTS "${CMAKE_BINARY_DIR}/conan.cmake")
    message(STATUS "Downloading conan.cmake from https://github.com/conan-io/cmake-conan")
    file(DOWNLOAD "https://raw.githubusercontent.com/conan-io/cmake-conan/0.18.1/conan.cmake"
            "${CMAKE_BINARY_DIR}/conan.cmake"
            TLS_VERIFY ON)
endif()
include(${CMAKE_BINARY_DIR}/conan.cmake)

conan_cmake_configure(REQUIRES boost/1.80.0
                               tinyxml2/9.0.0
                               libarchive/3.6.1
                      GENERATORS cmake_find_package
                                 virtualenv
                      OPTIONS tinyxml2:shared=False
                              boost:shared=False
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
conan_cmake_autodetect(settings)
conan_cmake_install(PATH_OR_REFERENCE .
                    PROFILE_HOST ../profiles/armv8.profile
                    PROFILE_BUILD ../profiles/build.profile
                    BUILD missing)

# Set conan environment variables generated using the virtualenv generator
# This is necessary since for some reason Conan does not correctly set the variables found (e.g. the Android NDK compiler path)
# A particular attention should be paid to the PATH variable since it is not good to completely overwrite it
if(EXISTS "${CMAKE_BINARY_DIR}/environment.sh.env")
    FILE(READ "${CMAKE_BINARY_DIR}/environment.sh.env" _contents)
    STRING(REGEX REPLACE "\n" ";" _contents "${_contents}")
    foreach(_line ${_contents})
        string(REGEX MATCH "([^=]+)=\"(.*)\"" _match ${_line})
        if(NOT "${_match}" STREQUAL "" AND NOT "${CMAKE_MATCH_1}" STREQUAL "PATH")
            #message("in ${CMAKE_MATCH_1} = ${CMAKE_MATCH_2}")
            set(ENV{${CMAKE_MATCH_1}} "${CMAKE_MATCH_2}")
        endif()
    endforeach()
    unset(_contents)
    unset(_line)
    unset(_match)
else()
    message(FATAL_ERROR "Android NDK environment variables not found!")
endif()

#set(CMAKE_C_COMPILER   $ENV{CC})
#set(CMAKE_CXX_COMPILER $ENV{CXX})
##set(CMAKE_CXX_COMPILER_AR $ENV{AR})
##set(CMAKE_CXX_COMPILER_RANLIB $ENV{RANLIB})
#set(CMAKE_AR           $ENV{AR})
#set(CMAKE_AS           $ENV{AS})
#set(CMAKE_RANLIB       $ENV{RANLIB})
#set(CMAKE_STRIP        $ENV{STRIP})
#set(CMAKE_ADDR2LINE    $ENV{ADDR2LINE})
#set(CMAKE_NM           $ENV{NM})
#set(CMAKE_OBJCOPY      $ENV{OBJCOPY})
#set(CMAKE_OBJDUMP      $ENV{OBJDUMP})
#set(CMAKE_READELF      $ENV{READELF})
#set(CMAKE_LD           $ENV{LD})

include(./CMakeListsProject.txt)
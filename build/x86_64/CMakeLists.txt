if (POLICY CMP0048)
    cmake_policy(SET CMP0048 NEW)
endif (POLICY CMP0048)

cmake_minimum_required(VERSION 3.20)

set(CMAKE_VERBOSE_MAKEFILE ON)

# Require out-of-source builds
file(TO_CMAKE_PATH "${PROJECT_BINARY_DIR}/CMakeLists.txt" LOC_PATH)
if(EXISTS "${LOC_PATH}")
    message(FATAL_ERROR "You cannot build in a source directory (or any directory with a CMakeLists.txt file). Please make a build subdirectory. Feel free to remove CMakeCache.txt and CMakeFiles.")
endif()

# Set a default build type if none was specified
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    message(STATUS "Setting build type to 'Release' as none was specified.")
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build." FORCE)
    # Set the possible values of build type for cmake-gui
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif()

project(ptracer VERSION 0.1.0
                DESCRIPTION "Library and utility tool that can inspect all the system calls performed by a process together with their stack traces"
                HOMEPAGE_URL "https://github.com/MaDeG/ptracer"
                LANGUAGES CXX)

if(NOT EXISTS "${CMAKE_BINARY_DIR}/conan.cmake")
    message(STATUS "Downloading conan.cmake from https://github.com/conan-io/cmake-conan")
    file(DOWNLOAD "https://raw.githubusercontent.com/conan-io/cmake-conan/0.18.1/conan.cmake" "${CMAKE_BINARY_DIR}/conan.cmake" TLS_VERIFY ON)
endif()
include(${CMAKE_BINARY_DIR}/conan.cmake)

conan_cmake_configure(REQUIRES libunwind/1.6.2
                                boost/1.80.0
                      GENERATORS cmake
                      OPTIONS boost:without_atomic=False
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
                    BUILD missing
                    SETTINGS ${settings})

include(${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
conan_basic_setup()

find_package(Threads REQUIRED)

file(GLOB SRC CONFIGURE_DEPENDS "../../src/*.cpp" "../../src/x86_64/*.cpp" "../../src/decoders/*.cpp" "../../src/dto/*.cpp")
message(STATUS "Source files:")
foreach (_s ${SRC})
    get_filename_component(_s "${_s}" ABSOLUTE)
    message(STATUS "${_s}")
endforeach()

add_library(prtracer-objects OBJECT ${SRC})
# shared libraries need PIC
set_property(TARGET prtracer-objects PROPERTY POSITION_INDEPENDENT_CODE 1
                                              CXX_STANDARD 23)

add_executable(ptracer $<TARGET_OBJECTS:prtracer-objects>)
# Build shared library
##add_library(ptracer-shared SHARED $<TARGET_OBJECTS:prtracer-objects>)
##set_target_properties(ptracer-shared PROPERTIES VERSION ${PROJECT_VERSION}
##                                     PUBLIC_HEADER ../../src/TracingManager.h)
##install(TARGETS ptracer-shared
##        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
##        PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
# Build static library
add_library(ptracer-static STATIC $<TARGET_OBJECTS:prtracer-objects>)
set_target_properties(ptracer-static PROPERTIES VERSION ${PROJECT_VERSION}
                                     PUBLIC_HEADER ../../src/TracingManager.h)
install(TARGETS ptracer-static
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

set_target_properties(ptracer PROPERTIES LINK_SEARCH_START_STATIC ON
                                         LINK_SEARCH_END_STATIC ON)

include_directories(${CONAN_INCLUDE_DIRS})

#Boost::program_options Boost::thread libunwind::libunwind
target_link_libraries(ptracer PRIVATE ${CONAN_LIBS} -static-libgcc -static-libstdc++)
target_link_libraries(ptracer-static PRIVATE ${CONAN_LIBS} -static-libgcc -static-libstdc++)
#target_link_libraries(ptracer-shared PRIVATE ${CONAN_LIBS} -static-libgcc -static-libstdc++)

set(EXTRA_FLAGS "-c -Werror -Wall -Wextra -MMD -Wall -Wextra -Wconversion -Wsign-conversion")
set(EXTRA_FLAGS "-fexceptions -frtti -fstack-protector-all -Wstack-protector -ftrapv -Wno-unused-but-set-variable -Wformat -Wformat-security -D_FORTIFY_SOURCE=2 -U_FORTIFY_SOURCE -fvisibility=hidden -fvisibility-inlines-hidden")
target_compile_options(ptracer PRIVATE ${CMAKE_C_FLAGS} ${EXTRA_FLAGS})
target_compile_options(ptracer-static PRIVATE ${CMAKE_C_FLAGS} ${EXTRA_FLAGS})
#target_compile_options(ptracer-shared PRIVATE ${CMAKE_C_FLAGS} ${EXTRA_FLAGS})

# Needed for the usage of the correct data structures to extract process information via ptrace
add_compile_definitions(ARCH_X86_64)
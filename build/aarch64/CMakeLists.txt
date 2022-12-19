cmake_minimum_required(VERSION 3.23)

cmake_policy(SET CMP0048 NEW)
# Avoid warning about DOWNLOAD_EXTRACT_TIMESTAMP in CMake 3.24:
if (CMAKE_VERSION VERSION_GREATER_EQUAL "3.24.0")
    cmake_policy(SET CMP0135 NEW)
endif()

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

project(ptracer
        VERSION 0.1.0
        DESCRIPTION "Library and utility tool that can inspect all the system calls performed by a process together with their stack traces"
        HOMEPAGE_URL "https://github.com/MaDeG/ptracer"
        LANGUAGES CXX)

include(${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
conan_basic_setup()

include_directories(${PROJECT_SOURCE_DIR}/src/aarch64 ${PROJECT_SOURCE_DIR}/src)

include(FetchContent)
FetchContent_Declare(libunwindstack-ndk
                     GIT_REPOSITORY https://github.com/MaDeG/libunwindstack-ndk
                     GIT_TAG master
                     GIT_SUBMODULES ""
                     SOURCE_SUBDIR cmake)
FetchContent_MakeAvailable(libunwindstack-ndk)
FetchContent_GetProperties(libunwindstack-ndk)

include(ExternalProject)
set(LIBALF_DIR ${CMAKE_BINARY_DIR}/libalf)
# Hack to retrieve the Android NDK compiler and pass it to Libalf Makefile, to be removed when a new automata library will be implemented
string(REGEX REPLACE "-$" "${ANDROID_NATIVE_API_LEVEL}-${CMAKE_ANDROID_NDK_TOOLCHAIN_VERSION}" LIBALF_CC_COMPILER ${CMAKE_CXX_ANDROID_TOOLCHAIN_PREFIX})
set(LIBALF_CXX_COMPILER "${LIBALF_CC_COMPILER}++")
ExternalProject_Add(libalf-src GIT_REPOSITORY git@github.com:MaDeG/libalf.git
                               GIT_TAG master
                               BUILD_IN_SOURCE TRUE
                               CONFIGURE_COMMAND ""
                               BUILD_COMMAND ""
                               INSTALL_COMMAND mkdir -p ${LIBALF_DIR}/include -p ${LIBALF_DIR}/lib
                                       COMMAND CC=${LIBALF_CC_COMPILER} AR=${CMAKE_AR} PREFIX=${LIBALF_DIR} make -C libAMoRE install
                                       COMMAND CXX=${LIBALF_CXX_COMPILER} AR=${CMAKE_AR} CPPFLAGS=-I${LIBALF_DIR}/include LDFLAGS=-L${LIBALF_DIR}/lib PREFIX=${LIBALF_DIR} CXXFLAGS=-std=c++14 make -C libAMoRE++ install
                                       COMMAND CXX=${LIBALF_CXX_COMPILER} AR=${CMAKE_AR} CPPFLAGS=-I${LIBALF_DIR}/include LDFLAGS=-L${LIBALF_DIR}/lib PREFIX=${LIBALF_DIR} CXXFLAGS=-std=c++14 make -C libalf install
                               PREFIX ${LIBALF_DIR}
                               BUILD_BYPRODUCTS ${LIBALF_DIR}/lib/libalf.a ${LIBALF_DIR}/lib/libAMoRE.a ${LIBALF_DIR}/lib/libAMoRE++.a)
ExternalProject_Get_Property(libalf-src INSTALL_DIR)
add_library(libalf STATIC IMPORTED)
add_library(libAMoRE STATIC IMPORTED)
add_library(libAMoRE++ STATIC IMPORTED)
set_target_properties(libalf PROPERTIES IMPORTED_LOCATION ${LIBALF_DIR}/lib/libalf.a)
set_target_properties(libAMoRE PROPERTIES IMPORTED_LOCATION ${LIBALF_DIR}/lib/libAMoRE.a)
set_target_properties(libAMoRE++ PROPERTIES IMPORTED_LOCATION ${LIBALF_DIR}/lib/libAMoRE++.a)

file(GLOB SRC CONFIGURE_DEPENDS "../../src/*.cpp" "../../src/aarch64/*.cpp" "../../src/decoders/*.cpp" "../../src/dto/*.cpp")
message(STATUS "Source files:")
foreach (_s ${SRC})
    get_filename_component(_s "${_s}" ABSOLUTE)
    message(STATUS "${_s}")
endforeach()

add_library(ptracer-objects OBJECT ${SRC})
# shared libraries need PIC
set_target_properties(ptracer-objects PROPERTIES POSITION_INDEPENDENT_CODE 1
                                                 CXX_STANDARD 23)
add_dependencies(ptracer-objects libalf-src)

add_executable(ptracer $<TARGET_OBJECTS:ptracer-objects>)
add_dependencies(ptracer libalf-src)
# Build shared library
#add_library(ptracer-shared SHARED $<TARGET_OBJECTS:ptracer-objects>)
#set_target_properties(ptracer-shared PROPERTIES VERSION ${PROJECT_VERSION}
#                                                PUBLIC_HEADER ../../src/TracingManager.h)
#install(TARGETS ptracer-shared
#        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
#        PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
#add_dependencies(ptracer-shared libalf-src)
# Build static library
add_library(ptracer-static STATIC $<TARGET_OBJECTS:ptracer-objects>)
set_target_properties(ptracer-static PROPERTIES VERSION ${PROJECT_VERSION}
                                                PUBLIC_HEADER ../../src/TracingManager.h)
install(TARGETS ptracer-static
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
add_dependencies(ptracer-static libalf-src)

target_link_libraries(ptracer PRIVATE ${CONAN_LIBS} unwindstack lzma libalf libAMoRE libAMoRE++)
#target_link_libraries(ptracer-shared PRIVATE ${CONAN_LIBS} unwindstack lzma libalf libAMoRE libAMoRE++)
target_link_libraries(ptracer-static PRIVATE ${CONAN_LIBS} unwindstack lzma libalf libAMoRE libAMoRE++)

include_directories(${CONAN_INCLUDE_DIRS}
                    ${libunwindstack-ndk_SOURCE_DIR}/include
                    ${LIBALF_DIR}/include)

set(EXTRA_FLAGS "-c -Werror -Wall -Wextra -MMD -Wall -Wextra -Wconversion -Wsign-conversion")
set(EXTRA_FLAGS "-fexceptions -frtti -fstack-protector-all -Wstack-protector -ftrapv -Wno-unused-but-set-variable -Wformat -Wformat-security -D_FORTIFY_SOURCE=2 -U_FORTIFY_SOURCE -fvisibility=hidden -fvisibility-inlines-hidden")
target_compile_options(ptracer PRIVATE ${CMAKE_C_FLAGS} ${EXTRA_FLAGS})
target_compile_options(ptracer-static PRIVATE ${CMAKE_C_FLAGS} ${EXTRA_FLAGS})
#target_compile_options(ptracer-shared PRIVATE ${CMAKE_C_FLAGS} ${EXTRA_FLAGS})

# Needed for the usage of the correct data structures to extract process information via ptrace
add_compile_definitions(ARCH_AARCH64)
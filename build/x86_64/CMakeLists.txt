cmake_minimum_required(VERSION 3.22)
project(ptracer)

set(CMAKE_VERBOSE_MAKEFILE ON)
SET(Boost_DEBUG TRUE)

if(NOT EXISTS "${CMAKE_BINARY_DIR}/conan.cmake")
    message(STATUS "Downloading conan.cmake from https://github.com/conan-io/cmake-conan")
    file(DOWNLOAD "https://raw.githubusercontent.com/conan-io/cmake-conan/0.18.1/conan.cmake"
            "${CMAKE_BINARY_DIR}/conan.cmake"
            TLS_VERIFY ON)
endif()
include(${CMAKE_BINARY_DIR}/conan.cmake)

conan_cmake_autodetect(settings)
conan_cmake_configure(REQUIRES libunwind/1.6.2
                               boost/1.80.0
                      GENERATORS cmake_find_package
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
conan_cmake_install(PATH_OR_REFERENCE .
                    BUILD missing
                    SETTINGS ${settings})

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_BINARY_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -c -g -Werror -Wall -Wextra -MMD -Wall -Wextra -Wconversion -Wsign-conversion")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector-all -Wstack-protector -ftrapv -Wno-unused-but-set-variable -Wformat -Wformat-security -D_FORTIFY_SOURCE=2 -U_FORTIFY_SOURCE -fvisibility=hidden")

set(Boost_USE_STATIC_LIBS ON)
find_package(Boost 1.40 COMPONENTS program_options log REQUIRED)
find_package(libunwind REQUIRED)
find_package(Threads REQUIRED)
#set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${LIBUNWIND_LIBRARIES}")

file(GLOB SRC CONFIGURE_DEPENDS "../../src/*.h" "../../src/*.cpp")
add_executable(ptracer ${SRC})
message("Source files: ${SRC}")

add_compile_definitions(ARCH_X86_64 USE_LIBUNWIND)

set_target_properties(ptracer PROPERTIES LINK_SEARCH_START_STATIC ON LINK_SEARCH_END_STATIC ON)

target_link_libraries(ptracer PRIVATE Boost::program_options Boost::thread libunwind::libunwind -static-libgcc -static-libstdc++)

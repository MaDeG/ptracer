cmake_minimum_required(VERSION 3.22)
project(ptracer)

set(CMAKE_VERBOSE_MAKEFILE ON)

SET(Boost_DEBUG TRUE)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${PROJECT_SOURCE_DIR}/../../CMakeModules)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -c -g -Werror -Wall -Wextra -MMD -Wall -Wextra -Wconversion -Wsign-conversion")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector-all -Wstack-protector -ftrapv -Wno-unused-but-set-variable -Wformat -Wformat-security -D_FORTIFY_SOURCE=2 -U_FORTIFY_SOURCE -fvisibility=hidden")

set(Boost_USE_STATIC_LIBS ON)
find_package(Boost 1.40 COMPONENTS program_options log REQUIRED)
find_package(libunwind REQUIRED)
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${LIBUNWIND_LIBRARIES}")
find_package(Threads REQUIRED)

file(GLOB SRC CONFIGURE_DEPENDS "../../src/*.h" "../../src/*.cpp")
add_executable(ptracer ${SRC})
message("Source files: ${SRC}")

add_compile_definitions(ARCH_X86_64 USE_LIBUNWIND)

set_target_properties(ptracer PROPERTIES LINK_SEARCH_START_STATIC ON LINK_SEARCH_END_STATIC ON)

target_link_libraries(ptracer PRIVATE Boost::program_options Boost::thread)

#target_link_libraries(ptracer PRIVATE -static-libgcc -static-libstdc++)

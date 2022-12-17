#!/bin/bash

cd "$(dirname "$0")" || exit 1
mkdir -p cmake-build-debug
cd cmake-build-debug || exit 1
conan install ../conanfile.txt --profile:build ../build.profile --profile:host ../armv8.profile --build missing
cmake .. -DCMAKE_TOOLCHAIN_FILE=conan_toolchain.cmake
make

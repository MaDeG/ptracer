#!/bin/bash

cd "$(dirname "$0")" || exit 1
conan create ../boost-conan-recipe madeg/boost --profile:build default --profile:host ./armv8.profile --build missing
mkdir -p cmake-build-debug
cd cmake-build-debug || exit 1
conan install ../conanfile.txt --profile:build default --profile:host ../armv8.profile --build missing
cmake .. -DCMAKE_TOOLCHAIN_FILE=conan_toolchain.cmake
make

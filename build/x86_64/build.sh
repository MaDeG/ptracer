#!/bin/bash

cd "$(dirname "$0")" || exit 1
conan create ../aarch64/boost-conan-recipe madeg/boost --build missing
mkdir -p cmake-build-debug
cd cmake-build-debug || exit 1
conan install ../conanfile.txt --build missing
cmake ..
make

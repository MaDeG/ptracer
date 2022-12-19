#!/bin/bash

cd "$(dirname "$0")" || exit 1
mkdir -p cmake-build-debug
cd cmake-build-debug || exit 1
conan install ../conanfile.txt --build missing
cmake ..
make

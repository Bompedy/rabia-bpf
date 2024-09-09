#!/bin/bash
mkdir -p build
cd build
export INTERFACE=enp4s0f1
cmake ..
cmake --build . --target run
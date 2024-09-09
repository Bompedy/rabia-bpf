#!/bin/bash
mkdir -p build
cd build
export INTERFACE=enp4s0f1

sudo tc qdisc add dev $INTERFACE clsact
if [ $? -ne 0 ]; then
    echo "Failed to add qdisc to $INTERFACE"
    exit 1
fi

cmake ..
cmake --build . --target run
#!/bin/bash
git config --global --add safe.directory /local/rabia-bpf
git pull
mkdir -p build
cd build
export INTERFACE=enp4s0f1

existing_qdisc=$(sudo tc qdisc show dev $INTERFACE | grep clsact)
if [ ! -z "$existing_qdisc" ]; then
    echo "Removing existing qdisc from $INTERFACE"
    sudo tc qdisc del dev $INTERFACE clsact
    if [ $? -ne 0 ]; then
        echo "Failed to remove existing qdisc from $INTERFACE"
        exit 1
    fi
fi

sudo tc qdisc add dev $INTERFACE clsact
if [ $? -ne 0 ]; then
    echo "Failed to add qdisc to $INTERFACE"
    exit 1
fi

cmake ..
cmake --build . --target run
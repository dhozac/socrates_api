#!/bin/bash
#
# any-network: Init script for bringing up one interface

for interface in $(ip link show | sed -n '/^[0-9]*: lo:/d; s/^[0-9]*: \([A-Za-z0-9_-]*\).*/\1/p'); do
    echo "Attempting to bring up $interface"
    if dhclient -1 $interface; then
        break
    fi
done
exit 0

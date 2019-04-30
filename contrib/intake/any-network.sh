#!/bin/bash
#
# any-network: Init script for bringing up one interface

interfaces=()
old_interfaces=()
while [ "${#interfaces[@]}" -lt 1 -o "${old_interfaces[*]}" != "${interfaces[*]}" ]; do
    old_interfaces=( "${interfaces[@]}" )
    sleep 3
    interfaces=( $(ip link show | sed -n '/^[0-9]*: lo:/d; s/^[0-9]*: \([A-Za-z0-9_-]*\).*/\1/p') )
done
for interface in "${interfaces[@]}"; do
    echo "Attempting to bring up $interface"
    if dhclient -1 $interface; then
        exit 0
    fi
done
exit 1

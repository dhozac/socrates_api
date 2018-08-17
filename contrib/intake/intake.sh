#!/bin/bash

. /etc/profile
if test "$#" -gt 0; then
    steps=( "$@" )
else
    steps=( $(cat /proc/cmdline | tr ' ' '\n' | sed -n 's/^step=//p') )
fi
hmac=$(cat /proc/cmdline | tr ' ' '\n' | sed -n 's/^hmac=//p')
nonce=$(cat /proc/cmdline | tr ' ' '\n' | sed -n 's/^nonce=//p')
exec /usr/sbin/intake-controller ${hmac:+-H $hmac} ${nonce:+-n $nonce} "${steps[@]}"

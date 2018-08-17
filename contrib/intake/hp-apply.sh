#!/bin/bash

e=0
for i in $(rpm -qal hp-firmware-* | grep '/.hpsetup$'); do
    pushd $(dirname $i)
    echo "y" | ./.hpsetup -s
    ret=$?
    test "$ret" -gt "$e" && e=$ret
    popd
done
exit "$e"

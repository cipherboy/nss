#!/bin/bash

source ~/.bashrc

rm out output.txt ../dist -rf ; ./build.sh -g --enable-fips --enable-libpkix || exit $?

cd tests/fips && CAVS_VECTORS=kbkdf HOST=localhost DOMSUF=localdomain ./fips.sh

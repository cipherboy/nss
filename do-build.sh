#!/bin/bash

source ~/.bashrc

gtcd ; rm out output.txt ../dist/ -rf ; ./build.sh -g --enable-fips --enable-libpkix && HOST=localhost DOMSUF=localdomain bash tests/gtests/gtests.sh > output.txt 2>&1 ; [ -e output.txt ] && vi output.txt

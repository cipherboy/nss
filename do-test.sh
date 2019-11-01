#!/bin/bash

source ~/.bashrc

gtcd


NSSDB_DIR="$(ls -d "$PWD/../tests_results/security"/*/gtests/pk11_gtest/ | head -n 1)"

echo "NSSDB Directory: $NSSDB_DIR"

cd ../ && LD_LIBRARY_PATH="dist/Debug/lib" gdb --args ./dist/Debug/bin/pk11_gtest -d "$NSSDB_DIR"

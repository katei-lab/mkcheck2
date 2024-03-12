#!/bin/bash
set -euxo pipefail

find Sources/mkcheck2abi/include/ Sources/mkcheck2bpf/mkcheck2.bpf.c \( -iname "*.h" -o -iname "*.c" \) -exec clang-format -i {} \;

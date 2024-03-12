#!/bin/bash

S="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

make -j4 -C "$S/gmake-jobserver" top

#!/bin/bash
set -e

S="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

clang "$S/stat.c" -o "$t/stat"

touch "$t/foo.txt"
ln -s "foo.txt" "$t/bar.txt"
"$t/stat" lstat "$t/bar.txt" &> /dev/null

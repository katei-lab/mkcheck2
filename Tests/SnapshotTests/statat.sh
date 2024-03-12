#!/bin/bash
set -e

S="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

clang "$S/statat.c" -o "$t/statat"

touch "$t/foo.txt"
"$t/statat" statx "$t" foo.txt &> /dev/null

# Basic stat command
touch "$t/bar.txt"
stat "$t/bar.txt" &> /dev/null

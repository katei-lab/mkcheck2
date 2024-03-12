#!/bin/bash
set -e

S="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

clang "$S/access.c" -o "$t/access"

touch "$t/foo.txt"
"$t/access" "$t/foo.txt" &> /dev/null

"$utils" faccess-at "$t" "foo.txt"

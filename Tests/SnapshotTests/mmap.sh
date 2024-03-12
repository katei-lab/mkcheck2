#!/bin/bash
set -e

S="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

clang "$S/mmap.c" -o "$t/mmap"

echo "hello" > "$t/foo.txt"
"$t/mmap" read "$t/foo.txt"

echo "world" > "$t/bar.txt"
"$t/mmap" write "$t/bar.txt"

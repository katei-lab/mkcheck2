#!/bin/bash
set -e

S="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

clang "$S/ftruncate.c" -o "$t/ftruncate"

echo "Hello, World!" > "$t/foo.txt"
"$t/ftruncate" "$t/foo.txt" 5

printf "Hello" > "$t/foo.expected"
diff "$t/foo.txt" "$t/foo.expected"

#!/bin/bash
set -e

S="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

clang "$S/link.c" -o "$t/link"

touch "$t/foo.txt"
"$t/link" link "$t/foo.txt" "$t/bar.txt"
"$t/link" symlink "foo.txt" "$t/baz.txt"

mkdir "$t/dir1"
touch "$t/dir1/foo.txt"
mkdir "$t/dir2"
"$utils" link-at "$t/dir1" "foo.txt" "$t/dir2" "bar.txt"

"$utils" symlink-at "$t/dir1" "foo.txt" "baz.txt"

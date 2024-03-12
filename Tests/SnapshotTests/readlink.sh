set -e

touch "$t/foo.txt"
ln -s "foo.txt" "$t/bar.txt"
ln -s "bar.txt" "$t/baz.txt"

"$utils" readlink "$t/bar.txt" | grep "foo.txt"
"$utils" readlink-at "$t" "baz.txt" | grep "bar.txt"

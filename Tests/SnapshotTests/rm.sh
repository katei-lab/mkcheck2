set -e

touch "$t/foo.txt"
touch "$t/bar.txt"

"$utils" unlink-at "$t" "foo.txt"

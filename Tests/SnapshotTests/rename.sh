set -e

mkdir "$t/dir1"
touch "$t/dir1/foo.txt"
mkdir "$t/dir2"

"$utils" rename-at "$t/dir1" "foo.txt" "$t/dir2" "bar.txt"

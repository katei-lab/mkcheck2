set -e

touch "$t/foo.txt"
"$utils" utime "$t/foo.txt"

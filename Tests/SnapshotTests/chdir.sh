set -eu
S="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cd $t

echo "Hello, world!" > ./bar.txt
$utils rename ./bar.txt ./baz.txt
cd -

clang "$S/chdir.c" -o "$t/chdir"

mkdir $t/baz
touch $t/baz/qux.txt
"$t/chdir" "$t/baz" qux.txt &> /dev/null

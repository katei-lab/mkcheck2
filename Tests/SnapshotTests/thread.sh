# Check that we trace threads correctly.

S="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
clang $S/thread.c -o $t/thread

cd $t
./thread

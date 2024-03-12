set -e
cat > $t/foo.c <<EOF
int main() {
    return 0;
}
EOF

clang -c $t/foo.c -o $t/foo.o

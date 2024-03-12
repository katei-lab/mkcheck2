set -e

echo "check" > "$t/foo.txt"

cat "$t/foo.txt" | xxd - "$t/bar.txt"

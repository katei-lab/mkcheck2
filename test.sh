#!/bin/bash

set -eu -o pipefail

print_usage() {
    echo "Usage: $0 [--update-snapshot]"
    echo ""
    echo "Options:"
    echo "  --update-snapshot  Update the expected output files"
}

while [ $# -gt 0 ]; do
    case $1 in
        "--update-snapshot")
            UPDATE_SNAPSHOT=1
            ;;
        "--help")
            print_usage
            exit 0
            ;;
        "--only")
            shift
            only_test=$1
            ;;
        *)
            echo "Unknown argument: $1"
            print_usage
            exit 1
            ;;
    esac
    shift
done

if [ -n "${UPDATE_SNAPSHOT:-}" ]; then
    echo -e "\033[0;33mUpdating snapshots...\033[0m"
fi

set -x
ninja -C build
touch Sources/mkcheck2/mkcheck2.swift
swift build --product mkcheck2
swift build --product mkcheck2-test-utils
{ set +x; } 2>/dev/null

test_suite=Tests/SnapshotTests
tmpdir="$test_suite.tmp"
rm -rf $tmpdir
mkdir -p $tmpdir

run_test() {
    local test_case=$1
    expected=$test_suite/$(basename $test_case .sh).txt
    out=$tmpdir/$(basename $test_case .sh).txt
    test_case_tmpdir=$tmpdir/$(basename $test_case .sh).tmp
    mkdir -p $test_case_tmpdir
    set -x
    sudo env t=$test_case_tmpdir utils=$PWD/.build/debug/mkcheck2-test-utils \
      $PWD/.build/debug/mkcheck2 -o $out --format ascii -- bash $test_case
    { set +x; } 2>/dev/null
    # Update the expected output if UPDATE_SNAPSHOT is set
    if [ -n "${UPDATE_SNAPSHOT:-}" ]; then
        diff -u $expected $out || (cp $out $expected && echo -e "\033[0;33mUpdated snapshot: $test_case\033[0m")
    else
        diff -u $expected $out || (echo -e "\033[0;31mTest failed: $test_case\033[0m" && exit 1)
        echo -e "\033[0;32mTest passed: $test_case\033[0m"
    fi
}

if [ -n "${only_test:-}" ]; then
    run_test $test_suite/$only_test.sh
else
    for test_case in $test_suite/*.sh; do
        run_test $test_case
    done
fi

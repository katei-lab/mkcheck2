#!/bin/bash
set -e

d="$t/check"

mkdir -p $d
touch $d/foo.txt
touch $d/bar.txt

ls $d

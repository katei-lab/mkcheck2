#!/bin/bash
set -ex

mkdir "$t/check1"
mkdir "$t/check2"
$utils remove-dir "$t/check1"

$utils mkdir-at "$t/check2" "check3"

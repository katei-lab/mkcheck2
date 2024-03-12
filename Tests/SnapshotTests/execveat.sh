#!/bin/bash
set -ex

$utils fork-execve-at "$(dirname "$utils")" "$(basename "$utils")" -- write --options create "$t/file1" "foo"

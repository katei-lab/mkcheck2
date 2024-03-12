#!/bin/bash

set -eu -o pipefail

BUILD_IN_DOCKER=0
CONFIGURATION=debug
SWIFTPM_ARGS=()
PASS_THROUGH_ARGS=()

while [ "$#" -gt 0 ]; do
  case "$1" in
    --docker)
      BUILD_IN_DOCKER=1
      shift
      ;;
    -c)
      CONFIGURATION="$2"
      PASS_THROUGH_ARGS+=("$1" "$2")
      shift 2
      ;;
    *)
      SWIFTPM_ARGS+=("$1")
      PASS_THROUGH_ARGS+=("$1")
      shift
      ;;
  esac
done

build_in_docker() {
  local image_tag="mkcheck2-build"
  docker build -t "$image_tag" --build-arg "MKCHECK2_BUILD_ARGS=${PASS_THROUGH_ARGS[*]}" .
  local container_id
  container_id=$(docker create "$image_tag")
  mkdir -p ".build/$CONFIGURATION"
  docker cp "$container_id":"/tmp/mkcheck2/.build/$CONFIGURATION/mkcheck2" ".build/$CONFIGURATION/mkcheck2"
  docker rm "$container_id"
}

if [ $BUILD_IN_DOCKER -eq 1 ]; then
  build_in_docker
  exit
fi

set -x
cmake -G Ninja -B build
cmake --build build
touch Sources/mkcheck2/mkcheck2.swift
swift build --product mkcheck2 "${SWIFTPM_ARGS[@]}" -c "$CONFIGURATION"

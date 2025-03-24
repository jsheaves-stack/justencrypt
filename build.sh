#!/bin/sh

MODE=${1:-dynamic}

echo "Building in $MODE mode"

docker build \
  --target "$MODE" \
  --build-arg BUILD_MODE="$MODE" \
  -t jsheaves/justencrypt:latest .

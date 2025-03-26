#!/bin/sh

MODE=${1:-dynamic}

echo "Building in $MODE mode"

docker build -t jsheaves/justencrypt:latest .

#!/bin/bash
# run-perf.sh - Professional Interactive JustEncrypt Performance Testing

set -e

# ANSI color codes
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}--- Performance Test Configuration ---${NC}"

# 1. Image Source
echo -e "${YELLOW}Where should we get the JustEncrypt binary?${NC}"
echo "1) Build locally from source (Default)"
echo "2) Use an existing Docker image"
echo "3) Skip build and use the existing 'justencrypt-perf' image"
read -p "Select [1-3]: " IMAGE_CHOICE
IMAGE_CHOICE=${IMAGE_CHOICE:-1}

if [ "$IMAGE_CHOICE" == "3" ]; then
    echo -e "${GREEN}Skipping build. Using existing image: justencrypt-perf${NC}"
else
    BINARY_SOURCE="builder"
    BINARY_PATH="/usr/src/justencrypt/target/x86_64-unknown-linux-musl/release/justencrypt"

    if [ "$IMAGE_CHOICE" == "2" ]; then
        read -p "$(echo -e ${YELLOW}"Enter Docker image name: "${NC})" PROVIDED_IMAGE
        BINARY_SOURCE="$PROVIDED_IMAGE"
        BINARY_PATH="/justencrypt"
    fi

    echo -e "\n${BLUE}--- Building Performance Test Environment ---${NC}"
    docker build -t justencrypt-perf -f Dockerfile.perf \
        --build-arg BINARY_SOURCE="$BINARY_SOURCE" \
        --build-arg BINARY_PATH="$BINARY_PATH" .
fi

# 2. Workload Configuration
echo -e "\n${BLUE}--- Load Parameters ---${NC}"
read -p "$(echo -e ${YELLOW}"Number of Virtual Users (Concurrency) [20]: "${NC})" VUS; VUS=${VUS:-20}
read -p "$(echo -e ${YELLOW}"Test Duration (e.g., 2m, 5m) [2m]: "${NC})" DURATION; DURATION=${DURATION:-2m}
read -p "$(echo -e ${YELLOW}"Sleep delay between iterations (seconds) [0.5]: "${NC})" SLEEP; SLEEP=${SLEEP:-0.5}

echo -e "\n${BLUE}--- File Configuration ---${NC}"
read -p "$(echo -e ${YELLOW}"Number of files per user session [10]: "${NC})" FILES_COUNT; FILES_COUNT=${FILES_COUNT:-10}
read -p "$(echo -e ${YELLOW}"Minimum file size (MB) [1]: "${NC})" MIN_SIZE; MIN_SIZE=${MIN_SIZE:-1}
read -p "$(echo -e ${YELLOW}"Maximum file size (MB) [100]: "${NC})" MAX_SIZE; MAX_SIZE=${MAX_SIZE:-100}

echo -e "\n${BLUE}--- Preparing Results Directory ---${NC}"
mkdir -p perf-results

echo -e "\n${BLUE}--- Starting Performance Test ---${NC}"
echo -e "${GREEN}Config: ${VUS} VUs, ${FILES_COUNT} files (${MIN_SIZE}-${MAX_SIZE} MB) each.${NC}"

docker run --rm \
    --ulimit memlock=-1:-1 \
    --ulimit nofile=65535:65535 \
    -e VUS="$VUS" \
    -e DURATION="$DURATION" \
    -e SLEEP="$SLEEP" \
    -e FILES_COUNT="$FILES_COUNT" \
    -e MIN_SIZE="$MIN_SIZE" \
    -e MAX_SIZE="$MAX_SIZE" \
    -v "$(pwd)/perf-results:/results" \
    justencrypt-perf

echo -e "\n${BLUE}--- Performance Test Complete ---${NC}"
echo -e "${GREEN}Report available: ./perf-results/PERFORMANCE_REPORT_<timestamp>.md${NC}"
echo -e "${GREEN}Raw metrics available: ./perf-results/k6_raw_metrics_<timestamp>.csv and ./perf-results/system_metrics_<timestamp>.csv${NC}"

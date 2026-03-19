#!/bin/bash
set -e

# Increase open file limit
ulimit -n 65535

# Set defaults
FILES_COUNT=${FILES_COUNT:-10}
MIN_SIZE=${MIN_SIZE:-1}
MAX_SIZE=${MAX_SIZE:-100}

# Dynamically create user data folders
echo "Setting up workspace for $VUS Virtual Users..."
mkdir -p user_data /results
for i in $(seq 1 $VUS); do
  mkdir -p "user_data/user_$i"
done
sync

# Generate random data based on user-requested max size
echo "Generating ${MAX_SIZE}MB test data source..."
head -c "$((MAX_SIZE * 1024 * 1024))" /dev/urandom > /perf-test/test_data.bin

# Start the JustEncrypt server
echo "Starting JustEncrypt API..."
./justencrypt &
SERVER_PID=$!

# Wait for server to respond
echo "Waiting for API to be healthy..."
until curl -s -f http://localhost:8000/ > /dev/null; do
  sleep 2
done

# Warm-up Phase
echo "Pre-initializing databases for $VUS users (Warm-up)..."
for i in $(seq 1 $VUS); do
  SUCCESS=false
  for attempt in {1..3}; do
    RESPONSE=$(curl -s -w "%{http_code}" -o /dev/null -X POST http://localhost:8000/session/create \
      -H "Content-Type: application/json" \
      -d "{\"username\": \"user_$i\", \"password\": \"TestPassword123!@#Stronger\"}")
    
    if [ "$RESPONSE" == "204" ]; then
      if [ -f "user_data/user_$i/user_$i.db" ]; then
        SUCCESS=true
        break
      fi
    fi
    sleep 1
  done
  if [ "$SUCCESS" = false ]; then
    echo "ERROR: Failed to initialize user_$i."
    kill $SERVER_PID
    exit 1
  fi
  sleep 0.05
done

echo "Warm-up complete. All $VUS databases are ready."

# --- Resource Monitor Start ---
METRICS_FILE="/results/system_metrics.csv"
echo "timestamp,cpu_pct,mem_mb" > "$METRICS_FILE"
(
  while true; do
    CPU=$(top -bn1 | grep "CPU:" | head -n1 | awk '{print $2 + $4}')
    MEM=$(free -m | awk '/Mem:/ {print $3}')
    echo "$(date +%s),$CPU,$MEM" >> "$METRICS_FILE"
    sleep 1
  done
) &
MONITOR_PID=$!

echo "Starting k6 performance test..."
JSON_REPORT="/results/report.json"

set +e
k6 run \
  -e VUS="$VUS" \
  -e DURATION="$DURATION" \
  -e SLEEP="$SLEEP" \
  -e FILES_COUNT="$FILES_COUNT" \
  -e MIN_SIZE="$MIN_SIZE" \
  -e MAX_SIZE="$MAX_SIZE" \
  --summary-export="$JSON_REPORT" \
  /perf-test/load-test.js
K6_EXIT=$?
set -e

# Shutdown Monitor and Server
kill $MONITOR_PID
kill $SERVER_PID

# --- Markdown Report Generation ---
echo "Generating Performance Markdown Report..."
MD_REPORT="/results/PERFORMANCE_REPORT.md"

# Parse Resource Metrics
MAX_CPU=$(awk -F, 'NR>1 {if($2>max) max=$2} END {print max}' "$METRICS_FILE")
AVG_CPU=$(awk -F, 'NR>1 {sum+=$2; count++} END {print sum/count}' "$METRICS_FILE")
MAX_MEM=$(awk -F, 'NR>1 {if($3>max) max=$3} END {print max}' "$METRICS_FILE")

# Parse k6 JSON
TOTAL_REQS=$(jq '.metrics.http_reqs.count' "$JSON_REPORT")
RPS=$(jq '.metrics.http_reqs.rate' "$JSON_REPORT")
SUCCESS_RATE=$(jq '.metrics.checks.value' "$JSON_REPORT")
DATA_RECV=$(jq '.metrics.data_received.count' "$JSON_REPORT")
DATA_SENT=$(jq '.metrics.data_sent.count' "$JSON_REPORT")
AVG_LATENCY=$(jq '.metrics.http_req_duration.avg' "$JSON_REPORT")
P95_LATENCY=$(jq '.metrics.http_req_duration."p(95)"' "$JSON_REPORT")

# Format metrics
RECV_MB=$(echo "scale=2; $DATA_RECV / 1048576" | bc)
SENT_MB=$(echo "scale=2; $DATA_SENT / 1048576" | bc)
FMT_RPS=$(printf "%.2f" $RPS)
FMT_SUCCESS=$(printf "%.2f" $(echo "$SUCCESS_RATE * 100" | bc -l))
FMT_AVG_LATENCY=$(printf "%.2f" $AVG_LATENCY)
FMT_P95_LATENCY=$(printf "%.2f" $P95_LATENCY)
FMT_AVG_CPU=$(printf "%.2f" $AVG_CPU)

cat <<EOF > "$MD_REPORT"
# JustEncrypt Performance Report
Generated on: $(date)

## 🚀 Test Configuration
| Parameter | Value |
|-----------|-------|
| Virtual Users (VUs) | $VUS |
| Target Duration | $DURATION |
| Iteration Sleep | ${SLEEP}s |
| Files per Session | $FILES_COUNT |
| File Size Range | ${MIN_SIZE} MB - ${MAX_SIZE} MB |

## 📊 High-Level Metrics
| Metric | Result |
|--------|--------|
| Total HTTP Requests | $TOTAL_REQS |
| Requests per Second (RPS) | ${FMT_RPS} req/s |
| Overall Success Rate | ${FMT_SUCCESS}% |
| Total Data Sent | ${SENT_MB} MB |
| Total Data Received | ${RECV_MB} MB |
| Avg. Request Latency | ${FMT_AVG_LATENCY} ms |
| 95th Percentile Latency | ${FMT_P95_LATENCY} ms |

## 🖥️ Resource Usage
| Resource | Peak | Average |
|----------|------|---------|
| CPU Usage | ${MAX_CPU}% | ${FMT_AVG_CPU}% |
| Memory Usage | ${MAX_MEM} MB | - |

## 📋 Detailed Performance Breakdown
| Check Name | Success Rate |
|------------|--------------|
$(jq -r '.root_group.checks | to_entries | .[] | "| " + .key + " | " + (((.value.passes / (.value.passes + .value.fails)) * 10000 | round / 100) | tostring) + "% |"' "$JSON_REPORT")

---
*Detailed technical data is available in report.json and system_metrics.csv*
EOF

echo "-----------------------------------------------"
echo "Report generated successfully: PERFORMANCE_REPORT.md"
echo "Peak CPU: ${MAX_CPU}% | Peak MEM: ${MAX_MEM}MB"
echo "Avg Throughput: ${FMT_RPS} req/s"
echo "-----------------------------------------------"

exit 0

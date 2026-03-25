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
    RESPONSE=$(curl -s -w "%{http_code}" -o /dev/null -X POST http://localhost:8000/session \
      -H "Content-Type: application/json" \
      -d "{\"username\": \"user_$i\", \"password\": \"TestPassword123!@#Stronger\"}")

    if [ "$RESPONSE" == "201" ]; then
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

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
# --- Resource Monitor Start ---
METRICS_FILE="/results/system_metrics_${TIMESTAMP}.csv"
echo "timestamp,cpu_pct,mem_mb" > "$METRICS_FILE"
(
  while true; do
    # Get CPU from top for the specific process (or fallback to 0)
    CPU=$(top -bn1 | grep "justencrypt" | head -n1 | awk '{print $7}' | sed 's/%//')
    CPU=${CPU:-0}
    
    # Get Memory (RSS) in KB from /proc
    MEM_KB=$(cat /proc/$SERVER_PID/status 2>/dev/null | grep VmRSS | awk '{print $2}')
    MEM_KB=${MEM_KB:-0}
    MEM=$((MEM_KB / 1024))
    
    echo "$(date +%s),$CPU,$MEM" >> "$METRICS_FILE"
    sleep 1
  done
) &
MONITOR_PID=$!

echo "Starting k6 performance test..."
JSON_REPORT="/results/report_${TIMESTAMP}.json"
CSV_REPORT="/results/k6_raw_metrics_${TIMESTAMP}.csv"

set +e
k6 run \
  -e VUS="$VUS" \
  -e DURATION="$DURATION" \
  -e SLEEP="$SLEEP" \
  -e FILES_COUNT="$FILES_COUNT" \
  -e MIN_SIZE="$MIN_SIZE" \
  -e MAX_SIZE="$MAX_SIZE" \
  --summary-export="$JSON_REPORT" \
  --out csv="$CSV_REPORT" \
  /perf-test/load-test.js
K6_EXIT=$?
set -e

# Shutdown Monitor and Server
kill $MONITOR_PID
kill $SERVER_PID

# --- Markdown Report Generation ---
echo "Generating Performance Markdown Report..."
MD_REPORT="/results/PERFORMANCE_REPORT_${TIMESTAMP}.md"

# Parse Resource Metrics
MAX_CPU=$(awk -F, 'NR>1 {if($2>max) max=$2} END {print max}' "$METRICS_FILE")
AVG_CPU=$(awk -F, 'NR>1 {sum+=$2; count++} END {print sum/count}' "$METRICS_FILE")
MAX_MEM=$(awk -F, 'NR>1 {if($3>max) max=$3} END {print max}' "$METRICS_FILE")
AVG_MEM=$(awk -F, 'NR>1 {sum+=$3; count++} END {print sum/count}' "$METRICS_FILE")

# Parse k6 JSON Metrics safely
TOTAL_REQS=$(jq '.metrics.http_reqs.count // 0' "$JSON_REPORT")
RPS=$(jq '.metrics.http_reqs.rate // 0' "$JSON_REPORT")
SUCCESS_RATE=$(jq '.metrics.checks.value // 0' "$JSON_REPORT")
DATA_RECV=$(jq '.metrics.data_received.count // 0' "$JSON_REPORT")
DATA_SENT=$(jq '.metrics.data_sent.count // 0' "$JSON_REPORT")
AVG_LATENCY=$(jq '.metrics.http_req_duration.avg // 0' "$JSON_REPORT")
P90_LATENCY=$(jq '.metrics.http_req_duration."p(90)" // 0' "$JSON_REPORT")
P95_LATENCY=$(jq '.metrics.http_req_duration."p(95)" // 0' "$JSON_REPORT")
P99_LATENCY=$(jq '.metrics.http_req_duration."p(99)" // 0' "$JSON_REPORT")

# Custom metrics parsing
UPLOAD_SUCCESS=$(jq '.metrics.upload_success_rate.value // 0' "$JSON_REPORT")
DOWNLOAD_SUCCESS=$(jq '.metrics.download_success_rate.value // 0' "$JSON_REPORT")
UPLOAD_AVG=$(jq '.metrics.upload_time.avg // 0' "$JSON_REPORT")
UPLOAD_P95=$(jq '.metrics.upload_time."p(95)" // 0' "$JSON_REPORT")
DOWNLOAD_AVG=$(jq '.metrics.download_time.avg // 0' "$JSON_REPORT")
DOWNLOAD_P95=$(jq '.metrics.download_time."p(95)" // 0' "$JSON_REPORT")
LOGIN_AVG=$(jq '.metrics.login_time.avg // 0' "$JSON_REPORT")
DELETE_AVG=$(jq '.metrics.delete_time.avg // 0' "$JSON_REPORT")

# Format metrics
RECV_MB=$(echo "scale=2; $DATA_RECV / 1048576" | bc)
SENT_MB=$(echo "scale=2; $DATA_SENT / 1048576" | bc)
FMT_RPS=$(printf "%.2f" $RPS)
FMT_SUCCESS=$(printf "%.2f" $(echo "$SUCCESS_RATE * 100" | bc -l))
FMT_UPLOAD_SUCCESS=$(printf "%.2f" $(echo "$UPLOAD_SUCCESS * 100" | bc -l))
FMT_DOWNLOAD_SUCCESS=$(printf "%.2f" $(echo "$DOWNLOAD_SUCCESS * 100" | bc -l))

FMT_AVG_LATENCY=$(printf "%.2f" $AVG_LATENCY)
FMT_P90_LATENCY=$(printf "%.2f" $P90_LATENCY)
FMT_P95_LATENCY=$(printf "%.2f" $P95_LATENCY)
FMT_P99_LATENCY=$(printf "%.2f" $P99_LATENCY)

FMT_UPLOAD_AVG=$(printf "%.2f" $UPLOAD_AVG)
FMT_UPLOAD_P95=$(printf "%.2f" $UPLOAD_P95)
FMT_DOWNLOAD_AVG=$(printf "%.2f" $DOWNLOAD_AVG)
FMT_DOWNLOAD_P95=$(printf "%.2f" $DOWNLOAD_P95)
FMT_LOGIN_AVG=$(printf "%.2f" $LOGIN_AVG)
FMT_DELETE_AVG=$(printf "%.2f" $DELETE_AVG)

FMT_AVG_CPU=$(printf "%.2f" ${AVG_CPU:-0})
FMT_AVG_MEM=$(printf "%.2f" ${AVG_MEM:-0})

# Health check indicators
SUCCESS_EMOJI=$([ "$(echo "$FMT_SUCCESS >= 99.0" | bc -l)" -eq 1 ] && echo "✅" || echo "⚠️")
UPLOAD_EMOJI=$([ "$(echo "$FMT_UPLOAD_SUCCESS >= 99.0" | bc -l)" -eq 1 ] && echo "✅" || echo "⚠️")
DOWNLOAD_EMOJI=$([ "$(echo "$FMT_DOWNLOAD_SUCCESS >= 99.0" | bc -l)" -eq 1 ] && echo "✅" || echo "⚠️")

cat <<EOF > "$MD_REPORT"
# 🚀 JustEncrypt Professional Performance Report
**Date:** $(date)

## 🛠️ Test Configuration
| Parameter | Value |
|-----------|-------|
| **Virtual Users (VUs)** | \`$VUS\` |
| **Duration** | \`$DURATION\` |
| **Iteration Sleep** | \`${SLEEP}s\` |
| **Files per User** | \`$FILES_COUNT\` |
| **File Size Range** | \`${MIN_SIZE} MB - ${MAX_SIZE} MB\` |

## 📊 Executive Summary
| Metric | Result | Status |
|--------|--------|--------|
| **Total Requests** | $TOTAL_REQS | ℹ️ |
| **Throughput (RPS)** | ${FMT_RPS} req/s | ℹ️ |
| **Overall Success Rate** | ${FMT_SUCCESS}% | $SUCCESS_EMOJI |
| **Upload Success Rate** | ${FMT_UPLOAD_SUCCESS}% | $UPLOAD_EMOJI |
| **Download Success Rate** | ${FMT_DOWNLOAD_SUCCESS}% | $DOWNLOAD_EMOJI |
| **Data Transferred** | ⬆️ ${SENT_MB} MB / ⬇️ ${RECV_MB} MB | ℹ️ |

## ⏱️ Latency Distribution (Overall)
| Percentile | Latency (ms) |
|------------|--------------|
| **Average** | ${FMT_AVG_LATENCY} ms |
| **p(90)** | ${FMT_P90_LATENCY} ms |
| **p(95)** | ${FMT_P95_LATENCY} ms |
| **p(99)** | ${FMT_P99_LATENCY} ms |

## 📂 Operation Specific Metrics
| Operation | Avg Latency (ms) | p(95) Latency (ms) |
|-----------|------------------|--------------------|
| **Authentication** | ${FMT_LOGIN_AVG} ms | N/A |
| **File Upload** | ${FMT_UPLOAD_AVG} ms | ${FMT_UPLOAD_P95} ms |
| **File Download** | ${FMT_DOWNLOAD_AVG} ms | ${FMT_DOWNLOAD_P95} ms |
| **File Deletion** | ${FMT_DELETE_AVG} ms | N/A |

## 🖥️ Resource Utilization (Server)
| Resource | Average | Peak |
|----------|---------|------|
| **CPU Usage** | ${FMT_AVG_CPU}% | ${MAX_CPU}% |
| **Memory Usage** | ${FMT_AVG_MEM} MB | ${MAX_MEM} MB |

## 📈 Raw Data Export
For deeper analysis, visualization, and dashboarding (e.g., in Grafana), the following raw data files have been generated:
- \`k6_raw_metrics_${TIMESTAMP}.csv\`: Raw k6 metrics suitable for Prometheus/Grafana or InfluxDB.
- \`system_metrics_${TIMESTAMP}.csv\`: Time-series system resource utilization (CPU/Memory).
- \`report_${TIMESTAMP}.json\`: Full JSON summary of the k6 test execution.

---
*Report automatically generated by JustEncrypt Performance Test Suite.*
EOF

echo "-----------------------------------------------"
echo "Report generated successfully: PERFORMANCE_REPORT_${TIMESTAMP}.md"
echo "Raw data exported to: k6_raw_metrics_${TIMESTAMP}.csv, system_metrics_${TIMESTAMP}.csv"
echo "Peak CPU: ${MAX_CPU}% | Peak MEM: ${MAX_MEM}MB"
echo "Avg Throughput: ${FMT_RPS} req/s"
echo "-----------------------------------------------"

exit 0

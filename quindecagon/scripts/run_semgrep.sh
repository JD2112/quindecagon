#!/usr/bin/env bash
source "$(dirname "$0")/../config/config.env"

mkdir -p ${RAW_DIR}

# Check if semgrep is installed
if ! command -v semgrep &> /dev/null; then
  echo "⚠️ semgrep not found. Skipping code scan."
  echo '{"status": "skipped", "reason": "semgrep not installed"}' > ${RAW_DIR}/semgrep.json
  exit 0
fi

# Run semgrep and save raw output
semgrep scan \
  --config auto \
  --json \
  --output ${RAW_DIR}/semgrep_raw.json \
  ${PIPELINE_DIR}

EXIT_CODE=$?

# Count issues from the raw output
ISSUES=$(jq '.results | length' ${RAW_DIR}/semgrep_raw.json 2>/dev/null || echo 0)

# Write a summary JSON with proper status field for the report
if [ "$ISSUES" -gt 0 ]; then
  echo "{\"status\": \"warning\", \"issues\": ${ISSUES}}" > ${RAW_DIR}/semgrep.json
  echo "⚠️ Semgrep found $ISSUES issues"
else
  echo '{"status": "passed", "issues": 0}' > ${RAW_DIR}/semgrep.json
  echo "✅ Semgrep clean"
fi
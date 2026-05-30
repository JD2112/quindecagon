#!/usr/bin/env bash
source "$(dirname "$0")/../config/config.env"

mkdir -p "${RAW_DIR}"

# Check if any .py files exist in PIPELINE_DIR
PY_FILES=$(find "${PIPELINE_DIR}" -name "*.py" 2>/dev/null)

if [ -z "$PY_FILES" ]; then
  echo "⚠️ No Python files found. Skipping Black format check."
  echo '{"status": "skipped", "unformatted_files": 0, "reason": "No Python files found"}' > "${RAW_DIR}/black.json"
  exit 0
fi

if ! command -v black &> /dev/null; then
  echo "⚠️ Black not found. Skipping Python formatting scan."
  echo '{"status": "skipped", "unformatted_files": 0, "reason": "Black not installed"}' > "${RAW_DIR}/black.json"
  exit 0
fi

echo "🔍 Running Black Python code format check on ${PIPELINE_DIR}..."

# Run black in check mode, save the diff if any
black --check --diff --exclude '\.nf-core|work|venv|\.venv|node_modules|tests|docs|site-packages|reports|report-check|\.git|assets|build|dist' "${PIPELINE_DIR}" > "${RAW_DIR}/black_raw.txt" 2>&1
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
  # Calculate how many files would be reformatted (lines starting with 'would reformat')
  REFORMAT_COUNT=$(grep -c "would reformat" "${RAW_DIR}/black_raw.txt" || echo 0)
  echo "{\"status\": \"warning\", \"unformatted_files\": ${REFORMAT_COUNT}}" > "${RAW_DIR}/black.json"
  echo "⚠️ Black check failed: ${REFORMAT_COUNT} files are unformatted."
else
  echo '{"status": "passed", "unformatted_files": 0}' > "${RAW_DIR}/black.json"
  echo "✅ Black format check clean."
fi

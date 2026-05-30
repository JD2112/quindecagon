#!/usr/bin/env bash
source "$(dirname "$0")/../config/config.env"

mkdir -p "${RAW_DIR}"

# Check if any .py files exist in PIPELINE_DIR
PY_FILES=$(find "${PIPELINE_DIR}" -name "*.py" 2>/dev/null)

if [ -z "$PY_FILES" ]; then
  echo "⚠️ No Python files found. Skipping Flake8 scan."
  echo '{"status": "skipped", "issues": 0, "reason": "No Python files found"}' > "${RAW_DIR}/flake8.json"
  exit 0
fi

if ! command -v flake8 &> /dev/null; then
  echo "⚠️ Flake8 not found. Skipping Python code quality scan."
  echo '{"status": "skipped", "issues": 0, "reason": "Flake8 not installed"}' > "${RAW_DIR}/flake8.json"
  exit 0
fi

echo "🔍 Running Flake8 Python code quality linter on ${PIPELINE_DIR}..."

#flake8 --exclude=.nf-core,work,venv,.venv,node_modules,tests,docs,site-packages,reports,report-check,.git,assets,build,dist --ignore=E501,W503 --format=json --output-file="${RAW_DIR}/flake8_raw.json" --exit-zero "${PIPELINE_DIR}" 2>/dev/null

flake8 --exclude=.nf-core,work,venv,.venv,node_modules,tests,docs,site-packages,reports,report-check,.git,assets,build,dist \
       --ignore=E501,W503 \
       --format=json \
       --output-file="${RAW_DIR}/flake8_raw.json" \
       --exit-zero "${PIPELINE_DIR}" 2>/dev/null

# Parse results using jq to sum the array lengths across all files
ISSUES=$(jq '[.[] | length] | add // 0' "${RAW_DIR}/flake8_raw.json" 2>/dev/null || echo 0)

if [ "$ISSUES" -gt 0 ]; then
  echo "{\"status\": \"warning\", \"issues\": ${ISSUES}}" > "${RAW_DIR}/flake8.json"
  echo "⚠️ Flake8 found ${ISSUES} Python code quality or styling issues."
else
  echo '{"status": "passed", "issues": 0}' > "${RAW_DIR}/flake8.json"
  echo "✅ Flake8 Python code quality clean."
fi

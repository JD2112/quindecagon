#!/usr/bin/env bash
source "$(dirname "$0")/../config/config.env"

mkdir -p "${RAW_DIR}"

# Check if any .py files exist in PIPELINE_DIR
PY_FILES=$(find "${PIPELINE_DIR}" -name "*.py" 2>/dev/null)

if [ -z "$PY_FILES" ]; then
  echo "⚠️ No Python files found. Skipping Bandit scan."
  echo '{"status": "skipped", "issues": 0, "high": 0, "reason": "No Python files found"}' > "${RAW_DIR}/bandit.json"
  exit 0
fi

if ! command -v bandit &> /dev/null; then
  echo "⚠️ Bandit not found. Skipping Python security scan."
  echo '{"status": "skipped", "issues": 0, "high": 0, "reason": "Bandit not installed"}' > "${RAW_DIR}/bandit.json"
  exit 0
fi

echo "🔍 Running Bandit Python SAST scan on ${PIPELINE_DIR}..."

bandit -r "${PIPELINE_DIR}" -x '.nf-core,work,venv,.venv,node_modules,tests,docs,site-packages,reports,report-check,.git,assets,build,dist' -f json -o "${RAW_DIR}/bandit_raw.json" 2>/dev/null

# Parse results using jq
ISSUES=$(jq '.results | length' "${RAW_DIR}/bandit_raw.json" 2>/dev/null || echo 0)
HIGH_ISSUES=$(jq '[.results[] | select(.issue_severity == "HIGH")] | length' "${RAW_DIR}/bandit_raw.json" 2>/dev/null || echo 0)

if [ "$HIGH_ISSUES" -gt 0 ]; then
  echo "{\"status\": \"failed\", \"issues\": ${ISSUES}, \"high\": ${HIGH_ISSUES}}" > "${RAW_DIR}/bandit.json"
  echo "❌ Bandit found ${HIGH_ISSUES} HIGH severity Python security vulnerabilities."
elif [ "$ISSUES" -gt 0 ]; then
  echo "{\"status\": \"warning\", \"issues\": ${ISSUES}, \"high\": 0}" > "${RAW_DIR}/bandit.json"
  echo "⚠️ Bandit found ${ISSUES} low/medium severity Python issues."
else
  echo '{"status": "passed", "issues": 0, "high": 0}' > "${RAW_DIR}/bandit.json"
  echo "✅ Bandit Python SAST clean."
fi

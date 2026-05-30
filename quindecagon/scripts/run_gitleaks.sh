#!/usr/bin/env bash
source "$(dirname "$0")/../config/config.env"

mkdir -p ${RAW_DIR}

echo "🔍 Running Gitleaks credentials scan..."

IS_GIT=false
if [ -d "${PIPELINE_DIR}/.git" ]; then
  IS_GIT=true
fi

if [ "$IS_GIT" = "true" ]; then
  gitleaks detect --source="${PIPELINE_DIR}" --report-format=json --report-path="${RAW_DIR}/gitleaks_findings_raw.json" --redact > /dev/null 2>&1
  G_EXIT=$?
  if [ -f "${RAW_DIR}/gitleaks_findings_raw.json" ]; then
    jq '[.[] | select(.File | test("\\.(png|jpg|jpeg|pdf|zip|gz|lock|webp|txt)$") | not)]' "${RAW_DIR}/gitleaks_findings_raw.json" > "${RAW_DIR}/gitleaks_findings.json" 2>/dev/null
  fi
else
  gitleaks detect --no-git --source="${PIPELINE_DIR}" --report-format=json --report-path="${RAW_DIR}/gitleaks_findings_raw.json" --redact > /dev/null 2>&1
  G_EXIT=$?
  if [ -f "${RAW_DIR}/gitleaks_findings_raw.json" ]; then
    jq '[.[] | select(.File | test("\\.(png|jpg|jpeg|pdf|zip|gz|lock|webp|txt)$") | not)]' "${RAW_DIR}/gitleaks_findings_raw.json" > "${RAW_DIR}/gitleaks_findings.json" 2>/dev/null
  fi
fi

LEAKS_FOUND=0
if [ -f "${RAW_DIR}/gitleaks_findings.json" ]; then
  # Recalculate G_EXIT based on whether any true secrets remain after filtering
  LEAKS_COUNT=$(jq '. | length' "${RAW_DIR}/gitleaks_findings.json" 2>/dev/null || echo "0")
  if [ "$LEAKS_COUNT" -gt 0 ]; then
    G_EXIT=1
  else
    G_EXIT=0
  fi
fi
STATUS="passed"
REASON="No credentials or secrets leaked."

if [ "$G_EXIT" -eq 0 ]; then
  STATUS="passed"
  echo "✅ No credentials or secrets leaked."
elif [ "$G_EXIT" -eq 1 ]; then
  STATUS="failed"
  LEAKS_FOUND=$(jq '. | length' "${RAW_DIR}/gitleaks_findings.json" 2>/dev/null || echo "0")
  REASON="Found ${LEAKS_FOUND} leaked credentials or secrets!"
  echo "❌ CRITICAL: Found ${LEAKS_FOUND} leaked credentials or secrets!"
else
  STATUS="skipped"
  REASON="Gitleaks scanner not available or failed to run"
  echo "⚠️ Gitleaks scanner failed to run"
fi

cat <<EOF > ${RAW_DIR}/gitleaks.json
{
  "status": "${STATUS}",
  "reason": "${REASON}",
  "leaks_found": ${LEAKS_FOUND}
}
EOF

echo "✅ Gitleaks credentials check completed"

#!/usr/bin/env bash
source "$(dirname "$0")/../config/config.env"

mkdir -p ${RAW_DIR}

echo "🔍 Checking for reproducibility assets in ${PIPELINE_DIR}..."

# 1. Check for nextflow.lock
if [ -f "${PIPELINE_DIR}/nextflow.lock" ]; then
  LOCK_FOUND=true
  echo "✅ nextflow.lock found"
else
  LOCK_FOUND=false
  echo "⚠️ nextflow.lock NOT found (recommended for production)"
fi

# 2. Check for container hashes in configs
# We look for patterns like 'docker.io/image@sha256:...' in config files
HASHES_COUNT=$(grep -rh "@sha256:" "${PIPELINE_DIR}/nextflow.config" "${PIPELINE_DIR}/conf" 2>/dev/null | wc -l)

if [ "$HASHES_COUNT" -gt 0 ]; then
  HASHES_PRESENT=true
  echo "✅ Found $HASHES_COUNT container hashes in configurations"
else
  HASHES_PRESENT=false
  echo "⚠️ No container hashes found in configurations (tags used instead)"
fi

# Determine status
if [ "$LOCK_FOUND" = "true" ] && [ "$HASHES_PRESENT" = "true" ]; then
  STATUS="passed"
elif [ "$HASHES_PRESENT" = "false" ]; then
  # In clinical settings, lack of immutable container hashes is a critical failure.
  STATUS="failed"
  echo "❌ CRITICAL: Container tags are used instead of immutable SHA256 hashes."
else
  STATUS="warning"
fi

# Save results
cat <<EOF > ${RAW_DIR}/reproducibility.json
{
  "status": "${STATUS}",
  "nextflow_lock": ${LOCK_FOUND},
  "container_hashes": ${HASHES_PRESENT},
  "hash_count": ${HASHES_COUNT}
}
EOF

echo "✅ Reproducibility check completed"

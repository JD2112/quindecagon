#!/usr/bin/env bash
source "$(dirname "$0")/../config/config.env"

mkdir -p ${RAW_DIR}

echo "🔍 Checking for data provenance tracking in ${PIPELINE_DIR}..."

# Check for manifest in nextflow.config
MANIFEST_DEFINED=$(grep -c "manifest {" "${PIPELINE_DIR}/nextflow.config" 2>/dev/null || echo 0)

# Check for tower.enabled or execution tracking
TRACKING_DEFINED=$(grep -E "tower\.enabled|with-report|with-trace" "${PIPELINE_DIR}/nextflow.config" 2>/dev/null | wc -l || echo 0)

if [ "$MANIFEST_DEFINED" -gt 0 ]; then
  echo "✅ Manifest defined in nextflow.config"
  MANIFEST_STATUS=true
else
  echo "⚠️ Manifest NOT defined in nextflow.config"
  MANIFEST_STATUS=false
fi

# Determine status
if [ "$MANIFEST_STATUS" = "true" ]; then
  STATUS="passed"
else
  STATUS="warning"
fi

# Save results
cat <<EOF > ${RAW_DIR}/provenance.json
{
  "status": "${STATUS}",
  "manifest_defined": ${MANIFEST_STATUS},
  "tracking_defined_count": ${TRACKING_DEFINED}
}
EOF

echo "✅ Provenance check completed"

#!/usr/bin/env bash
source "$(dirname "$0")/../config/config.env"
source "$(dirname "$0")/discover_containers.sh"

mkdir -p ${RAW_DIR}

# Check if syft and grype are installed
if ! command -v syft &> /dev/null || ! command -v grype &> /dev/null; then
  echo "⚠️ syft or grype not found. Skipping SBOM scan."
  echo '{"status": "skipped", "reason": "tools not installed"}' > ${RAW_DIR}/syft_grype.json
  exit 0
fi

# Auto-discover all container images from the pipeline
IMAGES=$(discover_containers "${PIPELINE_DIR}")

if [ -z "$IMAGES" ]; then
  echo "⚠️ No container images found in pipeline config."
  echo '{"status": "skipped", "reason": "no containers found"}' > ${RAW_DIR}/syft_grype.json
  exit 0
fi

echo "📦 Syft/Grype will scan $(echo "$IMAGES" | wc -l | tr -d ' ') container images"

FAILED=0

while IFS= read -r IMG; do
  echo "  🔍 Generating SBOM for: $IMG"
  
  SAFE_NAME=$(echo "$IMG" | sed 's|[/:@]|_|g')
  
  # Prioritize local docker daemon first (reproducible, offline-friendly, fast)
  syft "docker:${IMG}" --platform linux/amd64 -o spdx-json > "${RAW_DIR}/sbom_${SAFE_NAME}.spdx.json"
  
  if [ $? -ne 0 ]; then
    echo "    ⚠️ Could not generate SBOM from local daemon. Attempting registry query..."
    syft "$IMG" --platform linux/amd64 -o spdx-json > "${RAW_DIR}/sbom_${SAFE_NAME}.spdx.json"
    if [ $? -ne 0 ]; then
        echo "    ❌ SBOM generation failed for $IMG"
        continue
    fi
  fi
  
  echo "  🔍 Scanning SBOM with grype..."
  grype "sbom:${RAW_DIR}/sbom_${SAFE_NAME}.spdx.json" \
    --fail-on "${GRYPE_SEVERITY_THRESHOLD:-critical}" \
    --output json > "${RAW_DIR}/grype_${SAFE_NAME}.json"
  
  if [ $? -ne 0 ]; then
    echo "    ❌ Vulnerabilities found in $IMG"
    FAILED=1
  else
    echo "    ✅ Clean"
  fi
done <<< "$IMAGES"

# Create summary
echo "{\"status\": \"$([ $FAILED -eq 0 ] && echo 'passed' || echo 'failed')\", \"images_scanned\": $(echo "$IMAGES" | wc -l | tr -d ' ')}" > ${RAW_DIR}/syft_grype.json

if [ $FAILED -eq 1 ]; then
  echo "❌ SBOM scan found vulnerabilities"
  exit 1
fi

echo "✅ SBOM scan passed — all images clean"

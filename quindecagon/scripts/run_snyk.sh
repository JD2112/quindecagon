#!/usr/bin/env bash
source "$(dirname "$0")/../config/config.env"
source "$(dirname "$0")/discover_containers.sh"

mkdir -p ${RAW_DIR}

# Check if snyk is installed
if ! command -v snyk &> /dev/null; then
  echo "⚠️ snyk not found. Skipping dependency scan."
  echo '{"status": "skipped", "reason": "snyk not installed"}' > ${RAW_DIR}/snyk.json
  exit 0
fi

# Auto-discover all container images from the pipeline
IMAGES=$(discover_containers "${PIPELINE_DIR}")

if [ -z "$IMAGES" ]; then
  echo "⚠️ No container images found in pipeline config."
  echo '{"status": "skipped", "reason": "no containers found"}' > ${RAW_DIR}/snyk.json
  exit 0
fi

echo "📦 Snyk will scan $(echo "$IMAGES" | wc -l | tr -d ' ') container images"

FAILED=0

while IFS= read -r IMG; do
  echo "  🔍 Scanning: $IMG"
  
  SAFE_NAME=$(echo "$IMG" | sed 's|[/:@]|_|g')
  
  snyk container test "$IMG" --platform=linux/amd64 \
    --json-file-output="${RAW_DIR}/snyk_${SAFE_NAME}.json" 2>/dev/null
  
  if [ $? -ne 0 ]; then
    # Snyk exits non-zero when vulnerabilities are found
    HIGH_COUNT=$(jq '[.vulnerabilities[]? | select(.severity == "critical")] | length' "${RAW_DIR}/snyk_${SAFE_NAME}.json" 2>/dev/null || echo 0)
    
    if [ "$HIGH_COUNT" -gt 0 ]; then
      echo "    ❌ Found ${HIGH_COUNT} vulnerabilities above threshold"
      FAILED=1
    else
      echo "    ⚠️ Issues found but below threshold"
    fi
  else
    echo "    ✅ Clean"
  fi
done <<< "$IMAGES"

# Create summary
echo "{\"status\": \"$([ $FAILED -eq 0 ] && echo 'passed' || echo 'failed')\", \"images_scanned\": $(echo "$IMAGES" | wc -l | tr -d ' ')}" > ${RAW_DIR}/snyk.json

if [ $FAILED -eq 1 ]; then
  echo "❌ Snyk found vulnerabilities above threshold"
  exit 1
fi

echo "✅ Snyk passed — all images clean"
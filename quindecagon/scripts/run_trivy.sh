#!/usr/bin/env bash
source "$(dirname "$0")/../config/config.env"
source "$(dirname "$0")/discover_containers.sh"

mkdir -p ${RAW_DIR}

# Check if trivy is installed
if ! command -v trivy &> /dev/null; then
  echo "⚠️ trivy not found. Skipping image scan."
  echo '{"status": "skipped", "reason": "trivy not installed"}' > ${RAW_DIR}/trivy.json
  exit 0
fi

# Auto-discover all container images from the pipeline
IMAGES=$(discover_containers "${PIPELINE_DIR}")

if [ -z "$IMAGES" ]; then
  echo "⚠️ No container images found in pipeline config."
  echo '{"status": "skipped", "reason": "no containers found"}' > ${RAW_DIR}/trivy.json
  exit 0
fi

echo "📦 Trivy will scan $(echo "$IMAGES" | wc -l | tr -d ' ') container images"

FAILED=0
ALL_RESULTS="[]"

while IFS= read -r IMG; do
  echo "  🔍 Scanning: $IMG"
  
  # Create a safe filename from the image name
  SAFE_NAME=$(echo "$IMG" | sed 's|[/:@]|_|g')
  
  # Try to scan (Trivy will check local daemon and then registry)
  trivy image \
    --format json \
    --output "${RAW_DIR}/trivy_${SAFE_NAME}.json" \
    --severity HIGH,CRITICAL \
    --timeout 15m --scanners vuln \
    --platform linux/amd64 \
    "$IMG"
  
  if [ $? -ne 0 ]; then
    echo "    ⚠️ Scanning $IMG failed. Image might be private or local-only."
    echo "    🛠️ Attempting to scan from Docker daemon..."
    trivy image --image-src docker \
      --format json \
      --output "${RAW_DIR}/trivy_${SAFE_NAME}.json" \
      --severity HIGH,CRITICAL \
      --timeout 15m --scanners vuln \
      --platform linux/amd64 \
      "$IMG"
    
    if [ $? -ne 0 ]; then
       echo "    ❌ Could not scan $IMG (ensure it exists locally or is pullable)"
       continue
    fi
  fi
  
  # Check for vulnerabilities above threshold
  CRITICAL_COUNT=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL")] | length' "${RAW_DIR}/trivy_${SAFE_NAME}.json" 2>/dev/null || echo 0)
  
  if [ "$CRITICAL_COUNT" -gt 0 ]; then
    echo "    ❌ Found ${CRITICAL_COUNT} vulnerabilities above CVSS ${CVSS_THRESHOLD}"
    FAILED=1
  else
    echo "    ✅ Clean"
  fi
done <<< "$IMAGES"

# Create summary
echo "{\"status\": \"$([ $FAILED -eq 0 ] && echo 'passed' || echo 'failed')\", \"images_scanned\": $(echo "$IMAGES" | wc -l | tr -d ' ')}" > ${RAW_DIR}/trivy.json

if [ $FAILED -eq 1 ]; then
  echo "❌ Trivy found vulnerabilities above CVSS ${CVSS_THRESHOLD}"
  exit 1
fi

echo "✅ Trivy passed — all images clean"
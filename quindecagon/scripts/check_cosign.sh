#!/usr/bin/env bash
source "$(dirname "$0")/../config/config.env"
source "$(dirname "$0")/discover_containers.sh"

mkdir -p ${RAW_DIR}

# Check if cosign is installed
if ! command -v cosign &> /dev/null; then
  echo "⚠️ cosign not found. Skipping signature verification."
  echo '{"status": "skipped", "reason": "cosign not installed"}' > ${RAW_DIR}/cosign.json
  exit 0
fi

# Auto-discover all container images from the pipeline
IMAGES=$(discover_containers "${PIPELINE_DIR}")

if [ -z "$IMAGES" ]; then
  echo "⚠️ No container images found in pipeline config."
  echo '{"status": "skipped", "reason": "no containers found"}' > ${RAW_DIR}/cosign.json
  exit 0
fi

echo "📦 Cosign will verify $(echo "$IMAGES" | wc -l | tr -d ' ') container images"

SIGNED=0
UNSIGNED=0
RESULTS="[]"

while IFS= read -r IMG; do
  echo "  🔍 Verifying: $IMG"
  
  SAFE_NAME=$(echo "$IMG" | sed 's|[/:@]|_|g')
  
  if [ -n "${COSIGN_PUBLIC_KEY}" ] && [ -f "${COSIGN_PUBLIC_KEY}" ]; then
    cosign verify --key "${COSIGN_PUBLIC_KEY}" "$IMG" > "${RAW_DIR}/cosign_${SAFE_NAME}.txt" 2>&1
  else
    # Attempt keyless verification
    cosign verify "$IMG" --insecure-ignore-tlog > "${RAW_DIR}/cosign_${SAFE_NAME}.txt" 2>&1
  fi
  
  if [ $? -eq 0 ]; then
    echo "    ✅ Signed"
    SIGNED=$((SIGNED + 1))
  else
    echo "    ⚠️ Not signed or verification failed"
    UNSIGNED=$((UNSIGNED + 1))
  fi
done <<< "$IMAGES"

# Create summary
cat <<EOF > ${RAW_DIR}/cosign.json
{
  "status": "$([ $UNSIGNED -eq 0 ] && echo 'passed' || echo 'warning')",
  "signed": ${SIGNED},
  "unsigned": ${UNSIGNED},
  "total": $((SIGNED + UNSIGNED))
}
EOF

echo "========================================"
echo "✅ Signed: ${SIGNED}  |  ⚠️ Unsigned: ${UNSIGNED}"

# Don't fail the pipeline for unsigned images (common in dev)
# In production, uncomment the next line:
# [ $UNSIGNED -gt 0 ] && exit 1

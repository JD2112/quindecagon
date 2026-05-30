#!/usr/bin/env bash
source "$(dirname "$0")/../config/config.env"
source "$(dirname "$0")/discover_containers.sh"
export DOCKER_CONFIG="$HOME/.docker"

mkdir -p ${RAW_DIR}

echo "DEBUG: Discovering containers in: ${PIPELINE_DIR}"
IMAGES=$(discover_containers "${PIPELINE_DIR}")
echo "DEBUG: Found images: ${IMAGES}"

# Dynamically locate docker or standalone docker-scout binary
if command -v docker &> /dev/null && docker scout version &> /dev/null; then
  SCOUT_CMD="docker scout"
elif command -v docker-scout &> /dev/null; then
  SCOUT_CMD="docker-scout"
elif [ -f "/usr/local/bin/docker-scout" ]; then
  SCOUT_CMD="/usr/local/bin/docker-scout"
elif [ -f "/Applications/Docker.app/Contents/Resources/bin/docker" ]; then
  export PATH="/Applications/Docker.app/Contents/Resources/bin:$PATH"
  SCOUT_CMD="docker scout"
else
  echo "⚠️ docker-scout or docker scout not found. Skipping Docker Scout scan."
  echo '{"status": "skipped", "reason": "docker-scout not found"}' > "${RAW_DIR}/docker_scout.json"
  exit 0
fi

# Run docker context command only if docker CLI is available
if command -v docker &> /dev/null; then
  docker context use default > /dev/null 2>&1
fi

# Check if docker scout is functional
# if ! docker scout version > /dev/null 2>&1; then
#   echo "⚠️ docker scout plugin not found or not functional. Skipping Docker Scout scan."
#   echo '{"status": "skipped", "reason": "docker scout not functional"}' > "${RAW_DIR}/docker_scout.json"
#   exit 0
# fi


if [ -z "$IMAGES" ]; then
  echo "⚠️ No container images found in pipeline config."
  echo '{"status": "skipped", "reason": "no containers found"}' > ${RAW_DIR}/docker_scout.json
  exit 0
fi

echo "📦 Docker Scout will scan $(echo "$IMAGES" | wc -l | tr -d ' ') container images"

FAILED=0

# Remove the 'if ! docker scout version' check entirely 
# or change it to just a warning if you prefer.

# Loop through images
while IFS= read -r IMG; do
  echo "  🔍 Scanning: $IMG"
  
  # Clean up name for file system
  SAFE_NAME=$(echo "$IMG" | sed 's|[/:@]|_|g')
  
  # IMPORTANT: Use registry:// prefix for SHA-based images
  TARGET_IMG="registry://$IMG"
  
  # Run CVE scan
  # Capture output to a log file to help debug if it fails again
  $SCOUT_CMD cves "$TARGET_IMG" --platform linux/amd64 --only-severity critical,high \
    --exit-code \
    --format sarif > "${RAW_DIR}/docker_scout_${SAFE_NAME}_cves.json" 2> "${RAW_DIR}/docker_scout_${SAFE_NAME}_err.log"
  
  # Capture the exit code of the scan
  EXIT_CODE=$?
  
  if [ $EXIT_CODE -ne 0 ]; then
    # Exit code 1 usually means vulnerabilities were found
    # We check if the JSON is non-empty to distinguish between "vulns found" and "scan error"
    if [ -s "${RAW_DIR}/docker_scout_${SAFE_NAME}_cves.json" ]; then
        echo "    ❌ Vulnerabilities found above ${DOCKER_SCOUT_THRESHOLD}"
        FAILED=1
    else
        echo "    ⚠️ Scan error (Check ${RAW_DIR}/docker_scout_${SAFE_NAME}_err.log)"
    fi
  else
    echo "    ✅ Clean"
  fi
done <<< "$IMAGES"

# Create summary
echo "{\"status\": \"$([ $FAILED -eq 0 ] && echo 'passed' || echo 'failed')\", \"images_scanned\": $(echo "$IMAGES" | wc -l | tr -d ' ')}" > ${RAW_DIR}/docker_scout.json

if [ $FAILED -eq 1 ]; then
  echo "❌ Docker Scout found vulnerabilities above threshold"
  exit 1
fi

echo "✅ Docker Scout passed — all images clean"

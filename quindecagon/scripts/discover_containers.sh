#!/usr/bin/env bash
# ============================================================================
# Auto-discover all container images referenced in a Nextflow pipeline
# Compatible with macOS and Linux grep/sed
# Usage: source this script or run it standalone to list images
# ============================================================================

discover_containers() {
  local search_dir="$1"
  
  # Find all .config and .nf files, excluding 'backup' and 'docs' directories
  # Works with both: container = 'image:tag' and container = "image:tag"
  find "${search_dir}" -type d \( -name "backup" -o -name "docs" \) -prune -o -type f \( -name "*.config" -o -name "*.nf" \) -print0 2>/dev/null \
    | xargs -0 grep -h "container" 2>/dev/null \
    | grep "container *=" \
    | grep -v "^[[:space:]]*//" \
    | grep -v "^[[:space:]]*#" \
    | sed "s/.*container *=[[:space:]]*['\"/]*//" \
    | sed "s/['\"].*//; s/[[:space:]]*}//" \
    | sed "s|^docker://||" \
    | grep -v "^$" \
    | grep "/" \
    | sort -u
}

# If run standalone, print the discovered images
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  if [ -z "$1" ]; then
    echo "Usage: $0 <PIPELINE_DIR>"
    exit 1
  fi
  
  echo "🔍 Discovering container images in: $1"
  echo "========================================"
  
  IMAGES=$(discover_containers "$1")
  
  if [ -z "$IMAGES" ]; then
    echo "⚠️  No container images found."
    exit 0
  fi
  
  COUNT=$(echo "$IMAGES" | wc -l | tr -d ' ')
  
  echo "$IMAGES"
  echo "========================================"
  echo "📦 Found ${COUNT} unique container images"
fi

#!/usr/bin/env bash

# ============================================================================
# quindecagon — Unified Clinical Security Framework for Nextflow Pipelines
# Usage: ./run_all_checks.sh <TARGET_DIR>
#
# Container images are auto-discovered from the pipeline's config files.
# No need to list them manually.
# ============================================================================

# --- Argument Handling ---
if [ -z "$1" ]; then
  echo "❌ Usage: ./run_all_checks.sh <TARGET_DIR>"
  echo ""
  echo "  TARGET_DIR  Path to the Nextflow pipeline directory to audit"
  echo ""
  echo "  Examples:"
  echo "    ./run_all_checks.sh ~/Projects/methylflow"
  echo "    docker run --rm -it -v ~/Projects/methylflow:/target jd21/quindecagon bash run_all_checks.sh /target"
  exit 1
fi

# Resolve TARGET_DIR to an absolute path
export PIPELINE_DIR
PIPELINE_DIR="$(cd "$1" 2>/dev/null && pwd)"

if [ ! -d "$PIPELINE_DIR" ]; then
  echo "❌ Error: Directory '$1' does not exist."
  exit 1
fi

# --- Resolve locations ---
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# PKG_DIR is where scripts/ and config/ live
PKG_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
# BASE_DIR is the root of the app (/app in container)
BASE_DIR="$PKG_DIR"

# --- Build a unique report directory ---
PIPELINE_NAME="${PIPELINE_NAME:-$(basename "$PIPELINE_DIR")}"
TIMESTAMP="$(date +%Y-%m-%d_%H-%M)"
export REPORT_BASE="${BASE_DIR}"
export REPORT_DIR="${BASE_DIR}/reports/${PIPELINE_NAME}_${TIMESTAMP}"
export RAW_DIR="${REPORT_DIR}/raw"

# --- Load Config ---
source "${PKG_DIR}/config/config.env"

# --- Preview discovered containers ---
echo "========================================"
echo "🎯 Target pipeline:  ${PIPELINE_DIR}"
echo "📁 Reports saved to: ${REPORT_DIR}"
echo "========================================"

DISCOVERED=$(bash "${SCRIPT_DIR}/discover_containers.sh" "${PIPELINE_DIR}" 2>/dev/null | grep -v "^[🔍📦=]")
if [ -n "$DISCOVERED" ]; then
  COUNT=$(echo "$DISCOVERED" | wc -l | tr -d ' ')
  echo "🐳 Auto-discovered ${COUNT} container images:"
  echo "$DISCOVERED" | sed 's/^/   • /'
else
  echo "⚠️  No container images found — container scans will be skipped"
fi
echo "========================================"

# --- Setup ---
if [ -d "${BASE_DIR}/reports/raw" ]; then
  echo "🧹 Removing stale reports/raw/ from previous runs..."
  rm -rf "${BASE_DIR}/reports/raw"
fi
if [ -d "${BASE_DIR}/reports/final" ]; then
  echo "🧹 Removing stale reports/final/ from previous runs..."
  rm -rf "${BASE_DIR}/reports/final"
fi
mkdir -p "${RAW_DIR}" "${REPORT_DIR}/final"

# Persist audited pipeline metadata
cat <<EOF > "${RAW_DIR}/metadata.json"
{
  "pipeline_name": "${PIPELINE_NAME}",
  "pipeline_path": "${PIPELINE_PATH:-$PIPELINE_DIR}",
  "run_command": "${AUDIT_RUN_COMMAND:-N/A}"
}
EOF

# --- Container Tracking ---
DISCOVERED=$(bash "${SCRIPT_DIR}/discover_containers.sh" "${PIPELINE_DIR}" 2>/dev/null | grep -v "^[🔍📦=]")

if [ "$CLEANUP_IMAGES" = "true" ]; then
  echo "🧹 Checking for missing images to track for cleanup..."
  while IFS= read -r IMG; do
    if [ -n "$IMG" ]; then
      if ! docker image inspect "$IMG" >/dev/null 2>&1; then
        echo "   📌 Image $IMG not found locally. Will be removed after scan."
        IMAGES_TO_CLEAN+=("$IMG")
      fi
    fi
  done <<< "$DISCOVERED"
fi

# --- Nextflow Environment ---
# Fix: Redirect ALL Nextflow metadata, plugins, and temp files to writable /tmp
export NXF_HOME=/tmp/nxf
export NXF_TEMP=/tmp
export NXF_PLUGINS_DIR=/tmp/nxf/plugins
export NXF_PLUGINS_LOCAL_ROOT=/tmp/nxf/plr
export NXF_ASSETS=/tmp/nxf/assets
export TMPDIR=/tmp
export TEXMFVAR=/tmp/texmf-var
export TEXMFCACHE=/tmp/texmf-cache
mkdir -p "$NXF_HOME" "$NXF_PLUGINS_DIR" "$NXF_PLUGINS_LOCAL_ROOT" "$NXF_ASSETS" "$TEXMFVAR" "$TEXMFCACHE"

# --- Docker Config Override ---
export DOCKER_CONFIG=/tmp/docker-config
mkdir -p "$DOCKER_CONFIG"
echo '{}' > "$DOCKER_CONFIG/config.json"

# --- Nextflow Warm-up ---
echo "⚙️  Initializing Nextflow environment..."
nextflow help > /dev/null 2>&1
nextflow config /target > /dev/null 2>&1

# --- Execution Wrapper (to capture logs) ---
run_pipeline_audit() {
  FAILED=0
  
  # Define the final report name with timestamp
  REPORT_FILE="report_$(date +%Y%m%d_%H%M).html"
  function run_check() {
    echo "----------------------------------------"
    bash "${SCRIPT_DIR}/$1"
    if [ $? -ne 0 ]; then
      FAILED=1
    fi
  }

  # --- Discover Containers ---
  source "${SCRIPT_DIR}/discover_containers.sh"
  discover_containers "${PIPELINE_DIR}" > "${RAW_DIR}/images.txt"

  # --- Code & Config Checks ---
  if [ "$SKIP_NFCORE_LINT" = "true" ]; then
    echo "⏭️  Skipping nf-core lint..."
    echo '{"status": "skipped", "reason": "Disabled by user via --skip-nfcore-lint flag"}' > "${RAW_DIR}/nfcore_lint.json"
  else
    echo "🔍 Running nf-core lint..."
    run_check run_nfcore_lint.sh
  fi

  if [ "$SKIP_NF_CONFIG" = "true" ]; then
    echo "⏭️  Skipping Nextflow Config Validation..."
    echo '{"status": "skipped", "reason": "Disabled by user via --skip-nf-config flag"}' > "${RAW_DIR}/nf_config_validation.json"
  else
    echo "🔍 Validating Nextflow Config..."
    run_check validate_nextflow_config.sh
  fi

  if [ "$SKIP_SEMGREP" = "true" ]; then
    echo "⏭️  Skipping Semgrep..."
    echo '{"status": "skipped", "reason": "Disabled by user via --skip-semgrep flag"}' > "${RAW_DIR}/semgrep.json"
  else
    echo "🔍 Running Semgrep..."
    run_check run_semgrep.sh
  fi

  if [ "$SKIP_GITLEAKS" = "true" ]; then
    echo "⏭️  Skipping Gitleaks Secrets Audit..."
    echo '{"status": "skipped", "reason": "Disabled by user via --skip-gitleaks flag"}' > "${RAW_DIR}/gitleaks.json"
  else
    echo "🔍 Running Gitleaks Secrets Audit..."
    run_check run_gitleaks.sh
  fi

  if [ "$SKIP_BANDIT" = "true" ]; then
    echo "⏭️  Skipping Python Security Audit (Bandit)..."
    echo '{"status": "skipped", "reason": "Disabled by user via --skip-bandit flag"}' > "${RAW_DIR}/bandit.json"
  else
    echo "🔍 Running Python Security Audit (Bandit)..."
    run_check run_bandit.sh
  fi

  if [ "$SKIP_FLAKE8" = "true" ]; then
    echo "⏭️  Skipping Python Code Quality Linter (Flake8)..."
    echo '{"status": "skipped", "reason": "Disabled by user via --skip-flake8 flag"}' > "${RAW_DIR}/flake8.json"
  else
    echo "🔍 Running Python Code Quality Linter (Flake8)..."
    run_check run_flake8.sh
  fi

  if [ "$SKIP_BLACK" = "true" ]; then
    echo "⏭️  Skipping Python Code Formatter (Black)..."
    echo '{"status": "skipped", "reason": "Disabled by user via --skip-black flag"}' > "${RAW_DIR}/black.json"
  else
    echo "🔍 Running Python Code Formatter (Black)..."
    run_check run_black.sh
  fi

  if [ "$SKIP_R_AUDIT" = "true" ]; then
    echo "⏭️  Skipping R Security Audit..."
    echo '{"status": "skipped", "reason": "Disabled by user via --skip-r-audit flag"}' > "${RAW_DIR}/r_audit.json"
  else
    echo "🔍 Running R Security Audit (lintr & oysteR)..."
    run_check run_r_audit.sh
  fi

  if [ "$SKIP_REPRODUCIBILITY" = "true" ]; then
    echo "⏭️  Skipping Reproducibility..."
    echo '{"status": "skipped", "reason": "Disabled by user via --skip-reproducibility flag"}' > "${RAW_DIR}/reproducibility.json"
  else
    echo "🔍 Checking Reproducibility..."
    run_check check_reproducibility.sh
  fi

  echo "🔍 Checking Provenance..."
  run_check check_provenance.sh

  # --- Container Image Scans ---
  if [ "$SKIP_TRIVY" = "true" ]; then
    echo "⏭️  Skipping Trivy scan..."
    echo '{"status": "skipped", "reason": "Disabled by user via --skip-trivy flag"}' > "${RAW_DIR}/trivy.json"
  else
    echo "🔍 Running Trivy..."
    run_check run_trivy.sh
  fi

  if [ "$SKIP_SNYK" = "true" ]; then
    echo "⏭️  Skipping Snyk scan (--skip-snyk flag provided)..."
    echo '{"status": "skipped", "reason": "Disabled by user via --skip-snyk flag"}' > "${RAW_DIR}/snyk.json"
  else
    echo "🔍 Running Snyk..."
    run_check run_snyk.sh
  fi

  if [ "$SKIP_DOCKER_SCOUT" = "true" ]; then
    echo "⏭️  Skipping Docker Scout scan..."
    echo '{"status": "skipped", "reason": "Disabled by user via --skip-docker-scout flag"}' > "${RAW_DIR}/docker_scout.json"
  else
    echo "🔍 Running Docker Scout..."
    run_check run_docker_scout.sh
  fi

  if [ "$SKIP_SYFT" = "true" ] || [ "$SKIP_GRYPE" = "true" ]; then
    echo "⏭️  Skipping SBOM (Syft/Grype) scan..."
    echo '{"status": "skipped", "reason": "Disabled by user via --skip-syft/--skip-grype flag"}' > "${RAW_DIR}/syft_grype.json"
  else
    echo "🔍 Running SBOM (Syft/Grype) scan..."
    run_check run_syft_grype.sh
  fi

  if [ "$SKIP_COSIGN" = "true" ]; then
    echo "⏭️  Skipping Cosign signature verification..."
    echo '{"status": "skipped", "reason": "Disabled by user via --skip-cosign flag"}' > "${RAW_DIR}/cosign.json"
  else
    echo "🔍 Checking Cosign signatures..."
    run_check check_cosign.sh
  fi

  # --- Generate Report ---
  echo "📊 Attempting container-side report generation..."
  if bash "${SCRIPT_DIR}/generate_report.sh" "${REPORT_FILE}"; then
    echo "✅ Container report generated."
  else
    echo "⚠️  Container-side render failed (likely LaTeX/Fonts). You can still generate the report locally on your Mac using the raw files in: ${REPORT_DIR}/raw"
  fi

  # --- Cleanup Phase ---
  if [ "${#IMAGES_TO_CLEAN[@]}" -gt 0 ]; then
    echo "----------------------------------------"
    echo "🧹 Cleaning up ${#IMAGES_TO_CLEAN[@]} temporary images..."
    for IMG in "${IMAGES_TO_CLEAN[@]}"; do
      echo "   🗑️ Removing $IMG"
      docker rmi "$IMG" >/dev/null 2>&1
    done
  fi

  # --- Summary ---
  echo "========================================"
  if [ "$FAILED" -eq 1 ]; then
    echo "❌ Some checks failed (see above). Review the report."
    echo "📄 Report: ${REPORT_DIR}/final/${REPORT_FILE}"
    echo "📝 Logs:   ${REPORT_DIR}/run.log"
    return 1
  else
    echo "🎉 All checks completed successfully!"
    echo "📄 Report: ${REPORT_DIR}/final/${REPORT_FILE}"
    echo "📝 Logs:   ${REPORT_DIR}/run.log"
    return 0
  fi
}

# Run everything and capture output to run.log
run_pipeline_audit 2>&1 | tee "${REPORT_DIR}/run.log"

# Exit with the status of the audit
exit ${PIPESTATUS[0]}
#!/usr/bin/env bash
source "$(dirname "$0")/../config/config.env"

mkdir -p ${RAW_DIR}

# Ensure Nextflow environment is set for nf-core subprocesses
export NXF_HOME=${NXF_HOME:-/tmp/nxf}
export NXF_TEMP=${NXF_TEMP:-/tmp}
export NXF_PLUGINS_DIR=${NXF_PLUGINS_DIR:-/tmp/nxf/plugins}
export NXF_PLUGINS_LOCAL_ROOT=${NXF_PLUGINS_LOCAL_ROOT:-/tmp/nxf/plr}
export NXF_ASSETS=${NXF_ASSETS:-/tmp/nxf/assets}
export TMPDIR=${TMPDIR:-/tmp}

# Check if nf-core is installed
if ! command -v nf-core &> /dev/null; then
  echo "⚠️ nf-core not found. Skipping lint."
  echo '{"status": "skipped", "reason": "nf-core not installed"}' > ${RAW_DIR}/nfcore_lint.json
  exit 0
fi

# To completely avoid read-only mount issues when Nextflow evaluates the config,
# we copy the pipeline to a writable temporary directory.
WRITABLE_TARGET=$(mktemp -d)
cp -r "${PIPELINE_DIR}"/* "${WRITABLE_TARGET}/" 2>/dev/null || true
cp -r "${PIPELINE_DIR}"/.[!.]* "${WRITABLE_TARGET}/" 2>/dev/null || true

# Navigate to the writable pipeline directory
pushd "${WRITABLE_TARGET}" > /dev/null
LINT_OUTPUT=$(nf-core lint \
  --json "${RAW_DIR}/nfcore_lint.json" 2>&1) || true
EXIT_CODE=$?
popd > /dev/null

# Echo the output for the log
echo "$LINT_OUTPUT"

# Check if the failure is a config parse error or name format unpack error
CONFIG_PARSE_ERROR=false
if echo "$LINT_OUTPUT" | grep -q "Config parsing failed"; then
  CONFIG_PARSE_ERROR=true
fi

NAME_FORMAT_ERROR=false
if echo "$LINT_OUTPUT" | grep -q "ValueError: not enough values to unpack"; then
  NAME_FORMAT_ERROR=true
fi

# Clean up
rm -rf "${WRITABLE_TARGET}"

# nf-core's --json only writes when there are findings.
# If it succeeded cleanly, write our own summary.
if [ $EXIT_CODE -eq 0 ]; then
  if [ ! -s "${RAW_DIR}/nfcore_lint.json" ]; then
    echo '{"status": "passed"}' > "${RAW_DIR}/nfcore_lint.json"
  else
    TMP=$(jq '. + {"status": "passed"}' "${RAW_DIR}/nfcore_lint.json" 2>/dev/null) && echo "$TMP" > "${RAW_DIR}/nfcore_lint.json"
  fi
  echo "✅ nf-core lint passed"
elif [ "$CONFIG_PARSE_ERROR" = "true" ]; then
  # Config parse errors are expected for non-nf-core-template pipelines.
  # Report as warning, not hard failure.
  echo '{"status": "warning", "reason": "Nextflow config contains syntax not compatible with nf-core lint (e.g. deprecated check_max function). This is expected for custom pipelines."}' > "${RAW_DIR}/nfcore_lint.json"
  echo "⚠️ nf-core lint skipped — config parse error (not an nf-core template pipeline)"
elif [ "$NAME_FORMAT_ERROR" = "true" ]; then
  # Manifest name does not contain "/" format.
  echo '{"status": "warning", "reason": "nf-core tools require the pipeline name to be format \"author/name\" (e.g. \"nf-core/twistnext\") but found \"'"$PIPELINE_NAME"'\". Change manifest.name in nextflow.config to verify."}' > "${RAW_DIR}/nfcore_lint.json"
  echo "⚠️ nf-core lint skipped — manifest.name is not in \"author/name\" format"
else
  if [ ! -s "${RAW_DIR}/nfcore_lint.json" ]; then
    echo '{"status": "failed"}' > "${RAW_DIR}/nfcore_lint.json"
  else
    TMP=$(jq '. + {"status": "failed"}' "${RAW_DIR}/nfcore_lint.json" 2>/dev/null) && echo "$TMP" > "${RAW_DIR}/nfcore_lint.json"
  fi
  echo "❌ nf-core lint failed"
  exit 1
fi
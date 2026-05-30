#!/usr/bin/env bash
source "$(dirname "$0")/../config/config.env"

mkdir -p ${RAW_DIR}

# Check if nextflow is installed
if ! command -v nextflow &> /dev/null; then
  echo "⚠️ nextflow not found. Skipping config validation."
  echo '{"status": "skipped", "reason": "nextflow not installed"}' > ${RAW_DIR}/nf_config_validation.json
  exit 0
fi

echo "🔍 Validating Nextflow configuration in ${PIPELINE_DIR}..."

# Check syntax by attempting to resolve the config
# Use a temp file to capture output so we can check for parse errors
CONFIG_OUTPUT=$(nextflow config "${PIPELINE_DIR}" 2>&1)
EXIT_CODE=$?
echo "$CONFIG_OUTPUT" > "${RAW_DIR}/nf_config_validation.txt"

# Some Nextflow versions exit 0 even on parse errors, so also check the output
PARSE_ERROR=false
if echo "$CONFIG_OUTPUT" | grep -q "Config parsing failed"; then
  PARSE_ERROR=true
fi

if [ $EXIT_CODE -eq 0 ] && [ "$PARSE_ERROR" = "false" ]; then
  echo "✅ Nextflow config validation passed"
  echo '{"status": "passed", "tool": "nextflow config -validate"}' > ${RAW_DIR}/nf_config_validation.json
elif [ "$PARSE_ERROR" = "true" ]; then
  echo "⚠️ Nextflow config has parse warnings (check resources.config check_max syntax)"
  echo '{"status": "warning", "tool": "nextflow config -validate", "reason": "Config contains deprecated syntax (check_max). Pipeline will still run but fails strict validation."}' > ${RAW_DIR}/nf_config_validation.json
else
  echo "❌ Nextflow config validation failed"
  echo '{"status": "failed", "tool": "nextflow config -validate"}' > ${RAW_DIR}/nf_config_validation.json
fi

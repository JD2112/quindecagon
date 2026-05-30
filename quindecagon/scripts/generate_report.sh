#!/usr/bin/env bash
source "$(dirname "$0")/../config/config.env"

# Ensure the final output directory exists
mkdir -p "${REPORT_DIR}/final"

echo "🎨 Rendering security dashboard..."

# Get output filename from argument or default to report.html
OUTPUT_FILE="${1:-report.html}"

# Render the Quarto report to PDF (Formal Clinical Document)
export SECURITY_RAW_DIR="${RAW_DIR}"
export QUARTO_FORMAT=pdf
quarto render "$(dirname "$0")/../report.qmd" \
  --output-dir "${REPORT_DIR}/final" \
  --to pdf

echo "🎨 Generating interactive HTML dashboard..."
python3 "$(dirname "$0")/generate_html_dashboard.py" "${RAW_DIR}" "${REPORT_DIR}/final/report.html"



if [ $? -eq 0 ]; then
  echo "✅ Report generated successfully"
else
  echo "❌ Failed to generate report"
  exit 1
fi
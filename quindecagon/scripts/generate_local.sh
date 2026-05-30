#!/usr/bin/env bash
# ============================================================================
# Generate Security Report Locally (macOS)
# Use this when the container-side LaTeX rendering fails.
# ============================================================================

if [ -z "$1" ]; then
  echo "❌ Usage: ./generate_local.sh <REPORT_DIR>"
  echo "   Example: ./generate_local.sh reports/target_2026-05-09_15-54"
  exit 1
fi

# --- Path Handling ---
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PKG_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

REPORT_DIR="$1"
CWD="$(pwd)"

# Ensure REPORT_DIR is absolute (try CWD first, then PKG_DIR parent)
if [[ "$REPORT_DIR" != /* ]]; then
  if [ -d "$CWD/$REPORT_DIR" ]; then
    REPORT_DIR="$CWD/$REPORT_DIR"
  elif [ -d "$PKG_DIR/../$REPORT_DIR" ]; then
    REPORT_DIR="$PKG_DIR/../$REPORT_DIR"
  fi
fi

RAW_DIR="${REPORT_DIR}/raw"

if [ ! -d "$RAW_DIR" ]; then
  echo "❌ Error: Raw data directory '$RAW_DIR' not found."
  exit 1
fi

echo "🎨 Rendering report locally on Mac..."
export SECURITY_RAW_DIR="$RAW_DIR"

# Ensure output directory exists
mkdir -p "${REPORT_DIR}/final"

# Render PDF
quarto render "$PKG_DIR/report.qmd" \
  --output-dir "${REPORT_DIR}/final" \
  --to pdf

# If Quarto nested the output directory under the project folder, copy it to the correct absolute destination
if [ -f "$PKG_DIR/reports/$(basename "$REPORT_DIR")/final/report.pdf" ]; then
  cp -f "$PKG_DIR/reports/$(basename "$REPORT_DIR")/final/report.pdf" "${REPORT_DIR}/final/report.pdf"
fi

# Render premium HTML dashboard
python3 "$SCRIPT_DIR/generate_html_dashboard.py" "${RAW_DIR}" "${REPORT_DIR}/final/report.html"

if [ $? -eq 0 ]; then
  echo "========================================"
  echo "🎉 Local report generated successfully!"
  echo "📄 HTML: ${REPORT_DIR}/final/report.html"
  echo "📄 PDF:  ${REPORT_DIR}/final/report.pdf"
  echo "========================================"
else
  echo "❌ Local render failed."
  exit 1
fi

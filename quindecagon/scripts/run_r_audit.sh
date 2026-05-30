#!/usr/bin/env bash
source "$(dirname "$0")/../config/config.env"

mkdir -p "${RAW_DIR}"

# Check if any .R, .r, .Rmd, or .rmd files, or DESCRIPTION/renv.lock exist
R_FILES=$(find "${PIPELINE_DIR}" \( -name "*.R" -o -name "*.r" -o -name "*.Rmd" -o -name "*.rmd" \) 2>/dev/null)
HAS_DESC=$(if [ -f "${PIPELINE_DIR}/DESCRIPTION" ] || [ -f "${PIPELINE_DIR}/renv.lock" ]; then echo "yes"; else echo ""; fi)

if [ -z "$R_FILES" ] && [ -z "$HAS_DESC" ]; then
  echo "⚠️ No R scripts or dependency manifests found. Skipping R audit."
  echo '{"status": "skipped", "issues": 0, "reason": "No R files found"}' > "${RAW_DIR}/r_audit.json"
  exit 0
fi

if ! command -v Rscript &> /dev/null; then
  echo "⚠️ Rscript not found. Skipping R security scan."
  echo '{"status": "skipped", "issues": 0, "reason": "R runtime not installed"}' > "${RAW_DIR}/r_audit.json"
  exit 0
fi

echo "🔍 Running R security audit (lintr SAST & oysteR SCA) on ${PIPELINE_DIR}..."

export AUDIT_TARGET_DIR="${PIPELINE_DIR}"
export AUDIT_RAW_DIR="${RAW_DIR}"

Rscript -e '
suppressPackageStartupMessages({
  has_jsonlite <- require(jsonlite, quietly = TRUE)
  has_lintr <- require(lintr, quietly = TRUE)
  has_oyster <- require(oysteR, quietly = TRUE)
  has_riskmetric <- require(riskmetric, quietly = TRUE)
})

if (!has_jsonlite) {
  stop("jsonlite R package is not installed.")
}

target_dir <- Sys.getenv("AUDIT_TARGET_DIR")
raw_dir <- Sys.getenv("AUDIT_RAW_DIR")

# 1. Run lintr SAST
lint_df <- data.frame()
if (has_lintr) {
  try({
    my_linters <- lintr::linters_with_defaults(
      non_portable_path_linter = lintr::nonportable_path_linter()
    )
    
    # Recursively locate all R and Rmd files
    r_files <- list.files(target_dir, pattern = "\\.[Rr](md)?$", recursive = TRUE, full.names = TRUE)
    # Exclude virtual environments, build, or hidden folders
    r_files <- r_files[!grepl("/(\\.|reports|raw|containers|__pycache__|\\.venv)/", r_files)]
    
    lint_list <- list()
    for (f in r_files) {
      tryCatch({
        res_lint <- lintr::lint(f, linters = my_linters)
        if (length(res_lint) > 0) {
          lint_list[[f]] <- as.data.frame(res_lint)
        }
      }, error = function(e) {
        message(paste("Warning: lintr failed on file", f, ":", e$message))
      })
    }
    
    if (length(lint_list) > 0) {
      lint_df <- do.call(rbind, lint_list)
    }
  }, silent = FALSE)
} else {
  message("Warning: lintr R package is missing. Skipping static linting.")
}

# 2. Run oysteR SCA
vulns <- list()
pkgs_to_check <- character(0)
if (has_oyster) {
  try({
    renv_file <- file.path(target_dir, "renv.lock")
    desc_file <- file.path(target_dir, "DESCRIPTION")
    
    if (file.exists(renv_file)) {
      message("DEBUG: Found renv.lock, running audit...")
      aud <- oysteR::audit_renv_lock(renv_file)
      if (is.data.frame(aud)) {
        if ("vulnerable" %in% colnames(aud)) vulns <- aud[aud$vulnerable == TRUE, ]
        if ("package" %in% colnames(aud)) pkgs_to_check <- unique(aud$package)
      }
    } else if (file.exists(desc_file)) {
      aud <- oysteR::audit_description(desc_file)
      if (is.data.frame(aud)) {
        if ("vulnerable" %in% colnames(aud)) vulns <- aud[aud$vulnerable == TRUE, ]
        if ("package" %in% colnames(aud)) pkgs_to_check <- unique(aud$package)
      }
    } else {
      message("No renv.lock or DESCRIPTION file found for oysteR audit.")
    } 
  }, silent = FALSE)
} else {
  message("Warning: oysteR R package is missing. Skipping dependency vulnerability scan.")
}

# 3. Run riskmetric heuristical evaluation
risk_df <- list()
if (has_riskmetric) {
  try({
    if (length(pkgs_to_check) > 0) {
      check_pkgs <- head(pkgs_to_check, 20)
      refs <- riskmetric::pkg_ref(check_pkgs)
      assessments <- riskmetric::pkg_assess(refs)
      scores <- riskmetric::pkg_score(assessments)
      if (nrow(scores) > 0) {
        risky <- scores[scores$pkg_score < 0.5, ]
        if (nrow(risky) > 0) risk_df <- risky[, c("package", "version", "pkg_score")]
      }
    } else c("utils", "stats")
  }, silent = FALSE)
} else {
  message("Warning: riskmetric R package is missing. Skipping package quality assessment.")
}

num_lints <- if (is.data.frame(lint_df)) nrow(lint_df) else 0
num_vulns <- if (is.data.frame(vulns)) nrow(vulns) else 0
total_issues <- num_lints + num_vulns

status <- ifelse(total_issues > 0, "warning", "passed")

out <- list(
  status = status,
  issues = total_issues,
  lint_count = num_lints,
  vuln_count = num_vulns,
  linters = if (num_lints > 0) lint_df else list(),
  vulnerabilities = if (num_vulns > 0) vulns else list(),
  risks = if (is.data.frame(risk_df) && nrow(risk_df) > 0) risk_df else list()
)

jsonlite::write_json(out, file.path(raw_dir, "r_audit_raw.json"), auto_unbox = TRUE)
jsonlite::write_json(list(status = status, issues = total_issues, lint_count = num_lints, vuln_count = num_vulns), file.path(raw_dir, "r_audit.json"), auto_unbox = TRUE)
' > "${RAW_DIR}/r_audit.log" 2>&1

if [ -f "${RAW_DIR}/r_audit.json" ]; then
  ISSUES=$(jq '.issues' "${RAW_DIR}/r_audit.json" 2>/dev/null || echo 0)
  if [ "$ISSUES" -gt 0 ]; then
    echo "⚠️ R security audit found ${ISSUES} unsafe code patterns / vulnerable packages."
  else
    echo "✅ R security audit clean."
  fi
else
  # Expose actual logs to stderr so bioinformaticians can troubleshoot
  echo "❌ R audit failed to execute. Raw error log below:" >&2
  cat "${RAW_DIR}/r_audit.log" >&2
  echo '{"status": "skipped", "issues": 0, "reason": "R execution error"}' > "${RAW_DIR}/r_audit.json"
fi

# Changelog

All notable changes to the **quindecagon** Clinical Pipeline Integrity & Security Framework will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to Semantic Versioning.

## [0.5.0] - 2026-10-02

### Added
- **Native CI Workflow Generation & Setup CLI**:
  - Added `quindecagon workflow create` and `quindecagon init-ci` commands to automatically generate GitHub Actions workflows for downstream Nextflow repositories.
  - Added automatic detection of GitHub repository metadata (`owner/repo`) from `git remote` or `nextflow.config` (`manifest.name`).
  - Added automated, idempotent injection of 7 dynamic Shields.io badge endpoints into downstream repository `README.md` files.
- **Centralized GitHub Actions Reusable Workflow**:
  - Implemented `.github/workflows/pipeline-audit.yml` callable across any bioinformatics pipeline (`uses: JD2112/quindecagon/.github/workflows/pipeline-audit.yml@main`).
  - Supports configurable container images, badges branch targets, artifact uploads, and dynamic badge deployment without code drift.
- **Automated PyPI Publishing Workflow**:
  - Added `.github/workflows/publish-pypi.yml` supporting Trusted Publishing (OIDC) and tag releases.
- **Unified CLI Entrypoint**:
  - Added top-level `quindecagon` command dispatcher supporting `workflow`, `init-ci`, `audit`, and `report` subcommands alongside existing `quindecagon-audit` and `quindecagon-report`.

### Fixed
- **Docker Wrapper Resiliency (`#2`)**: `docker_run.sh` now gracefully handles missing `.env` files rather than aborting, and removed legacy interactive enter prompts.
- **TinyTeX Installation in Dockerfile (`#3`)**: Added `tlmgr update --self` before installing packages to prevent build failures against updated CTAN repositories.
---

## [0.4.0] - 2026-05-25

### Added
- **Clinical Compliance Assessment Gatekeeper**:
  - Integrated an automated **Consensus Compliance Assessment Engine** in `quindecagon/report.qmd` and `quindecagon/scripts/generate_html_dashboard.py` to evaluate pipeline runs using a risk-based 4-level deficiency model (**APPROVED**, **APPROVED WITH LIMITATIONS**, **WARNING**, **FAILED**).
  - Explicitly mapped the automated security gates to standard regulatory pathology references including **College of American Pathologists (CAP) Molecular Pathology NGS checklist items** (MOM.36000, MOM.36150, MOM.36200) and **ISO 15189:2022 §7.4** guidelines for medical software verification.
  - Implemented dynamic rendering of the clinical decision: outputs a beautifully-styled LaTeX `tcolorbox` (Green, Yellow, Orange, Red) in compiled PDF reports, and a matching Tailwind CSS glassmorphic card in the interactive HTML cockpit, detailing bypassed tools, coding style alerts, and domain-level deficiencies for complete audit compliance.
- **A4-Optimized Portrait Flowchart Layout**:
  - Re-engineered the clinical security gate flowchart (`hidden/workflow.mmd` and matching framework artifacts) from an excessively wide horizontal flow (`graph LR`) to an elegant, vertical top-to-bottom layout (`graph TD`) perfectly matching the standard A4 aspect ratio.
  - Embedded inline Mermaid initializer blocks (`%%{init: ... }%%`) to configure professional typography (Inter typeface), elegant basis curves, and custom compact spacing (vertical `rankSpacing: 40` and horizontal `nodeSpacing: 30`) directly within the diagram file itself.
  - Standardized node widths by wrapping long descriptive labels and multi-scanner titles using HTML line breaks (`<br>`), making individual elements highly readable and preventing severe scaling, truncation, or excessive margin padding when printing or rendering to PNG.
- **Zero-Configuration Cosign Public Key Mounting**: 
  - Added an automatic key detection and mount engine to `quindecagon/scripts/docker_run.sh` to seamlessly bridge the host Cosign public keys with the container sandbox.
  - The script now scans the host environment dynamically in the following order of precedence:
    1. Host environment variable `COSIGN_PUBLIC_KEY`
    2. Local secrets `.env` file parameter `COSIGN_PUBLIC_KEY`
    3. Default folder path `~/.cosign/cosign.pub`
    4. Current working directory `cosign.pub`
  - If a public key is discovered on the host, it is mounted as a read-only volume to `/app/cosign.pub:ro` inside the Docker runtime container, and the environment is overridden with `COSIGN_PUBLIC_KEY=/app/cosign.pub`.
  - This eliminates the need for manual configuration and prevents silent fallbacks to keyless verification which fail in containerized clinical environments.

- **Fine-Grained Auditing `--skip` CLI Flags**:
  - Implemented comprehensive `--skip-<tool>` command line options for all 15 core security, quality-assurance, and compliance checkers.
  - Users can now bypass specific checks (e.g. Snyk, Trivy, Gitleaks, etc.) while running standard audits by appending matching CLI flags (e.g. `--skip-snyk`, `--skip-docker-scout`, `--skip-r-audit`).
  - Standardized container environment variable exports and check wrappers inside the framework to log warnings and cleanly produce a `"status": "skipped"` json response, which is beautifully formatted as `Skipped` directly inside final HTML/PDF dashboards.
- **Clinical Validation References Integration**:
  - Mapped clinical compliance decisions directly to foundational academic and clinical validation papers (Lavrichenko et al., 2024; Ellingford et al., 2026; Ganzinger et al., 2021; Vidanagamachchi et al., 2024) inside the PDF bibliography.
  - Added a dedicated interactive **Clinical Literature** tab inside the HTML cockpit dashboard to render these academic citations dynamically.
- **Dynamic Docker Socket GID Detection**:
  - Implemented transient container GID checks inside the host `docker_run.sh` to handle virtualization socket ownership mismatch and dynamically attach the socket group using the `--group-add` flag, granting non-root container pipeline access to the Docker daemon.

### Fixed
- **Clinical Pipeline Metadata Traceability Bug**:
  - Fixed a namespace overriding bug in `quindecagon/scripts/run_all_checks.sh` where `PIPELINE_NAME` was hardcoded to `basename "/target"`, resulting in the generic name `target` in report headers and raw metadata.
  - Updated the resolution to preserve the pre-existing environment variable passed by the host script: `PIPELINE_NAME="${PIPELINE_NAME:-$(basename "$PIPELINE_DIR")}"`.
  - This guarantees clinical traceability (CAP checklist NGS item **MOM.36000**) by populating both the Quarto PDF and HTML Cockpit tables with the actual pipeline directory name (e.g. `quindecagon` or `TwistNext`) and host absolute path.
  - Report folders generated under `reports/` are now correctly namespaced (e.g. `reports/TwistNext_2026-05-25_08-08`) instead of the generic `reports/target_...`.

- **Docker Build Context Resolution Bug**:
  - Fixed a path resolution bug in `docker_run.sh` where compiling the container locally in a git development repository threw `lstat: no such file or directory` due to a hardcoded context path referencing `quindecagon/docker/Dockerfile`.
  - Replaced it with dynamic search-and-context detection supporting both local repository layouts (`quindecagon/../Dockerfile`) and packaged distribution structures seamlessly.

- **Cosign Compatibility & Signature Verification Engine Upgrade**:
  - Upgraded the compiled Sigstore `cosign` binary in the `Dockerfile` from `v2.4.1` to the modern **`v3.0.6`** to match the Mac host environment.
  - **Mismatched Signature Engine Parity**: Resolved a critical regression in Cosign v2 where images with multiple signature tags on the registry (signed by different keys, e.g. key transitions or multiple environments) would throw strict `comparing public key PEMs` Rekor bundle errors and abort the entire verification. Cosign v3 successfully filters and isolates signatures matching the specified trusted key.
  - **Signature Detection Bug**: Resolved an issue where newer `v3`-signed images (e.g., `milou_report` signed with v3) threw `no signatures found` under the old `v2.4.1` container runtime.
  - Updated version labels and static fallbacks in `quindecagon/report.qmd` and `quindecagon/scripts/generate_html_dashboard.py` to correctly reflect **`v3.0.6`** in all compiled reports and directory tables.
- **PDF Word Breaks & Table Layout Collisions**:
  - Upgraded Quarto rendering to parse typewriter absolute paths, run commands, and container image names with Pandoc raw inline LaTeX attributes (`{=latex}`) inside typewriter blocks. This prevents Pandoc from escaping backslashes to literal `\allowbreak` characters, allows natural hyphen/underscore wrapping, center-aligns status columns, and colors status badges for high-premium clinical presentation.
  - Extended raw inline LaTeX styling and `is_code=False` word-break wrapping to **Flake8, Bandit, Semgrep, Gitleaks, and R lintr** findings tables. This completely resolves literal backslash leakages (such as in `annotate_results.R` or `build_unified_results.py`), center-aligns numeric line/column columns, and prevents severe text collisions or overlaps in PDF outputs.
- **Registry Egress & Offline Scanner Stability**:
  - Swapped SBOM execution order inside `run_syft_grype.sh` to scan cached local Docker daemon targets first (`syft docker:${IMG}`), preventing network query delays, lookup rate limits, or DNS host crashes in strict air-gapped laboratory audits.

---

## [0.3.0] - 2026-05-21

### Added
- **Multi-Scanner Consensus Security**: Added concurrent parsing for Trivy, Snyk, Grype, Docker Scout, Syft SBOMs, and Cosign Signatures into a unified 6-tool consensus matrix.
- **Docker Scout Integration**: Integrated a robust standalone Docker Scout SARIF parsing system into the interactive HTML dashboard and Quarto reports.
- **R Security Audit (`lintr` Stability)**: Wrapped lintr executions in R script parsing blocks to ensure crashes on legacy files (like massive analytics scripts) are caught safely, allowing supply chain `oysteR` and package quality `riskmetric` checks to run successfully.
- **Gitleaks `.json` Leak Retention**: Refactored secret auditing exclusions in Quarto reports to only ignore the compilation output directories (`reports/`), preserving genuine credentials detected inside repository `.json` files.

---

## [0.2.0] - 2026-05-18

### Added
- **Dynamic Tool Version Extraction**: Built a custom Python helper `get_tool_version` to dynamically query active container CLI and R package versions (`trivy --version`, `cosign version`, `Rscript -e ...`) at render-time, automatically printing verified running versions in compiled HTML and PDF reports.
- **Unified Packaging & Editable Mode**: Standardized the code structure under standard Python package guidelines with `pyproject.toml` support for seamless local pip development (`pip install -e .`) and automatic clean Docker runtime rebuild triggers.
- **Bioconductor & R Package Audit**: Integrated a dedicated R lintr scanner along with dynamic dependency vulnerability auditing (`oysteR`) and maintenance scoring (`riskmetric`) to capture scientific library exposures missed by general static analysis.

### Fixed
- **Spelling Standardization**: Audited the entire codebase to correct all instances of `riskmetrics` to `riskmetric` to ensure dynamic command calls align perfectly with the target CRAN library namespace.

---

## [0.1.0] - 2026-05-10

### Added
- **Initial Release**: Launched the initial clinical pipeline containerized security suite under the version tag `nf-security-tools:0.1.x`.
- **Core Security Checkers**: Baked in a robust set of static code and container scanners:
  - Trivy and Snyk CLI for Docker image layer and container library vulnerabilities.
  - Gitleaks for scanning hardcoded secrets, API tokens, and access keys in pipeline repositories.
  - Bandit and Flake8 for custom Python script security flaws and PEP8 styling.
  - Black formatter to ensure code formatting determinism.
- **Quarto Report Engine**: Built a full HTML/PDF reporting dashboard leveraging Quarto, TinyTeX, and custom LaTeX packages.

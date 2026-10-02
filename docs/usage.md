---
hide:
  - navigation
---

# Usage Guide

**quindecagon** is packaged as a standard Python distribution and is fully containerized inside a hardened, minimal Ubuntu base image (`jd21/quindecagon:0.3.1`). This guide details how to configure, execute, and adapt audits to your local bioinformatics workflows.

---

## 1. Containerized Execution (Highly Recommended)

The simplest and most secure way to run audits is through the pre-packaged container. This requires no local installation of the 15 scanning tools or LaTeX/Quarto engines.

To run the audit on a Nextflow pipeline folder, execute the host helper script:

```bash
./quindecagon/scripts/docker_run.sh /path/to/nextflow/pipeline
```

### What happens under the hood?

1.  **Dynamic Socket Mapping**: The script probes the group ID (GID) of the host Docker socket `/var/run/docker.sock` inside the container namespace and attaches it via `--group-add`. This grants the container's non-root `pipeline` user secure permission to run local-daemon scans.
2.  **Target Mounting**: Mounts your Nextflow pipeline directory read-only to `/target` inside the sandbox.
3.  **Local-First Verification**: Automatically discovers all container images used in the pipeline configs and generates SBOMs locally using `syft docker:<img_name>` to guarantee fast, unauthenticated, 100% offline scanning.
4.  **Report Delivery**: Writes compiled PDF and HTML reports deterministically to `reports/<pipeline_name>_<timestamp>/final/`.

---

## 2. Fine-Grained CLI Bypass Flags

In clinical laboratory validation cycles, some SaaS-dependent checks or R dependency trees might need to be bypassed depending on your network architecture or pipeline configuration. **quindecagon** supports 15 granular skip flags to bypass individual checkers:

| CLI Bypass Flag          | Target Checker                       | Bypassed Category               |
| :----------------------- | :----------------------------------- | :------------------------------ |
| `--skip-snyk`            | Snyk CLI                             | SaaS Egress Container Consensus |
| `--skip-docker-scout`    | Docker Scout CLI                     | SaaS Egress Layer SAST          |
| `--skip-trivy`           | Trivy Image Scan                     | Local OS Vulnerability          |
| `--skip-syft`            | Syft SBOM                            | Software Bill of Materials SCA  |
| `--skip-grype`           | Grype Scan                           | Local SBOM Vulnerability        |
| `--skip-cosign`          | Cosign Signature                     | Supply Chain Verification       |
| `--skip-gitleaks`        | Gitleaks scan                        | Repository Secrets Scanning     |
| `--skip-semgrep`         | Semgrep engine                       | Nextflow Groovy Code SAST       |
| `--skip-bandit`          | Bandit scan                          | Python Code Security            |
| `--skip-flake8`          | Flake8 engine                        | Python Coding Style (PEP8)      |
| `--skip-black`           | Black formatter                      | Python Format Verification      |
| `--skip-r-audit`         | R checkers (lintr/oysteR/riskmetric) | R Statistical SAST & SCA        |
| `--skip-nfcore-lint`     | nf-core tools                        | Nextflow Structure Linter       |
| `--skip-nf-config`       | Config verifications                 | Locked Channel Names & Tags     |
| `--skip-reproducibility` | Reproducibility gate                 | `nextflow.lock` & Determinism   |

### Example Skipped Run

To run an audit in a strictly air-gapped clinical laboratory environment (which requires bypassing SaaS egress tools like Snyk and Docker Scout), run:

```bash
./quindecagon/scripts/docker_run.sh --skip-snyk --skip-docker-scout /path/to/pipeline
```

This forces the audit to run 100% offline, guaranteeing zero-data egress in HIPAA-sensitive networks.

---

## 3. Native / Conda Local Execution

If you wish to integrate quindecagon into an active developer setup or local CI/CD runner without using Docker, follow these steps.

### Prerequisites

Ensure the host system has the following binary tools installed and added to your `PATH`:

- `trivy`, `snyk`, `cosign`, `gitleaks`, `syft`, `grype`
- `quarto` (v1.9+) and `tinytex` / `pdftex` LaTeX engines
- `python3` and `R`

### Installation

Clone the repository and install the framework in editable development mode:

```bash
git clone https://github.com/JD2112/quindecagon.git
cd quindecagon
pip install -e .
```

### Local Audit Execution

Verify your dependencies and run all compliance checks natively:

```bash
bash quindecagon/scripts/run_all_checks.sh /path/to/pipeline
```

Once raw logs are generated in `reports/raw/`, compile the HTML dashboard and typeset PDF report locally:

```bash
./quindecagon/scripts/generate_local.sh reports/latest_run_folder
```

---

## 4. GitHub Actions CI/CD Integration

To automatically audit pipelines on push/pull request and display dynamic Shields.io status badges in your pipeline's `README.md`:

### Automated Setup (CLI)

```bash
# Install Quindecagon
pip install quindecagon
# (or directly from GitHub: pip install git+https://github.com/JD2112/quindecagon.git)
# (or run without installing via: pipx run quindecagon init-ci)

# In your target pipeline repository:
quindecagon init-ci
# or
quindecagon workflow create
```

### Zero-Install Setup (Manual)

If you prefer not to install Quindecagon locally, simply create `.github/workflows/quindecagon-audit.yml`:

This generates `.github/workflows/quindecagon-audit.yml`:

```yaml
name: Security & Compliance Audit

on:
  push:
    branches: [main, dev]
  pull_request:
    branches: [main, dev]
  workflow_dispatch:

permissions:
  contents: write

jobs:
  quindecagon-audit:
    name: 'Quindecagon Audit'
    uses: JD2112/quindecagon/.github/workflows/pipeline-audit.yml@main
    permissions:
      contents: write
    with:
      deploy-badges: true
```

The workflow runs Quindecagon inside `jd21/quindecagon:0.4.0` in root mode, generates dynamic JSON endpoints, and commits them to the target repo's `badges` branch for live Shields.io endpoint badges.

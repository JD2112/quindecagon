# quindecagon: Clinical Pipeline Integrity & Security Framework

![](images/quindecagon_logo.png)

**quindecagon** is a specialized security and compliance audit framework designed specifically for clinical Nextflow pipelines. By leveraging 15 distinct security and quality-assurance instruments, quindecagon ensures that your bioinformatics workflows are deterministic, secure, and ready for clinical validation.

### Why quindecagon?

In a clinical setting (CAP/CLIA/HIPAA), pipeline stability is not optional. **quindecagon** provides an automated, "defense-in-depth" validation gate that runs before any patient data is processed. It effectively eliminates the "silent drift" of container versions and prevents the introduction of insecure code or hardcoded credentials into the diagnostic environment.

### The 15 Faces of Security

**quindecagon** synthesizes outputs from the following 15 essential tools to provide a holistic, clinical-grade view of pipeline health:

#### **Code Quality & Linting**

* **[nf-core lint](https://www.google.com/search?q=https://nf-co.re/tools/)**: Ensures the pipeline adheres to the nf-core community's best practices and standardized structure.
* **[Flake8](https://flake8.pycqa.org/)**: Checks custom Python scripts for syntax errors, PEP 8 styling, and undefined variables.
* **[Black](https://black.readthedocs.io/)**: An uncompromising, deterministic Python code formatter to ensure style consistency.
* **[lintr](https://lintr.r-lib.org/)**: Performs static analysis on R code to enforce styling and detect potential syntax errors.

#### **Static Analysis (SAST)**

* **[Semgrep](https://semgrep.dev/)**: Analyzes Groovy/Nextflow source code to find security vulnerabilities and configuration bugs.
* **[Bandit](https://bandit.readthedocs.io/)**: Scans custom Python scripts for security anti-patterns and insecure library usage.
* **[oysteR](https://www.google.com/search?q=https://github.com/stephaniehicks/oysteR)**: Audits R package dependencies against the Sonatype OSS Index for known vulnerabilities.

#### **Supply Chain Integrity**
* **[Syft](https://github.com/anchore/syft)**: Generates a comprehensive Software Bill of Materials (SBOM) for container images.
* **[Cosign](https://github.com/sigstore/cosign)**: Handles container signing, verification, and provenance storage in OCI registries.

#### **Vulnerability Consensus**
* **[Trivy](https://www.google.com/search?q=https://aquasecurity.github.io/trivy/)**: Scans container images, file systems, and repositories for vulnerabilities.
* **[Snyk](https://snyk.io/)**: Scans container images for vulnerabilities in application dependencies and base-image packages.
* **[Grype](https://github.com/anchore/grype)**: Specializes in SBOM-based vulnerability scanning for container images and filesystems.
* **[Docker Scout](https://docs.docker.com/scout/)**: Provides integrated analysis of container images to identify and remediate security vulnerabilities.

#### **Secrets & Risk Management**
* **[Gitleaks](https://gitleaks.io/)**: Scans repositories for leaked API keys, tokens, and hardcoded credentials.
* **[riskmetric](https://github.com/pharmaR/riskmetric)**: Provides a quantitative framework for evaluating the risk associated with R package dependencies.

### Clinical Compliance Mapping

quindecagon maps its automated checks directly to regulatory requirements, providing laboratory directors with the verifiable documentation required for clinical accreditation:

* **CAP NGS Checklist**: Validates software integrity, component provenance, and reproducibility.
* **HIPAA Security Rule**: Ensures risk analysis, data integrity, and transmission security.

## 🚀 Quick Start

### Option A: Run directly (tools installed locally)

```bash
# Clone the security suite
git clone https://github.com/JD2112/quindecagon.git
cd quindecagon

# Run against your pipeline directory
./run_all_checks.sh /path/to/your/nextflow-pipeline
```

### Option B: Run via Docker (recommended)

Use the built-in, zero-configuration runner script to automatically build, mount, and run checks:

```bash
# Run against a pipeline directory on your host
./quindecagon/scripts/docker_run.sh /path/to/your/nextflow-pipeline
```

---

## 📖 Usage

```
./quindecagon/scripts/docker_run.sh [skip-options] <TARGET_DIR>
```

| Argument          | Required | Description                                                |
|-------------------|----------|------------------------------------------------------------|
| `TARGET_DIR`      | ✅       | Path to the Nextflow pipeline directory to audit           |

> **Auto-Discovery:** Container images are automatically parsed from your pipeline's
> `nextflow.config`, `conf/*.config`, and `*.nf` files. You never need to list them manually.

### Dynamic Skip Options (Fine-Grained Auditing)

You can selectively bypass one or more of the 15 audit checkers by passing `--skip-<tool>` CLI flags. Skipped tools are cleanly logged as warnings and reported as `Skipped` directly inside final HTML/PDF dashboards without halting the validation suite:

```bash
# Example: Skip heavy container consensus scanners (Snyk/Docker Scout)
./quindecagon/scripts/docker_run.sh --skip-snyk --skip-docker-scout ~/Projects/methylflow

# Example: Skip static checkers to only run reproducibility and signature verification
./quindecagon/scripts/docker_run.sh --skip-semgrep --skip-bandit --skip-r-audit ~/Projects/methylflow
```

#### Available Skip Flags:
* **Container Security:** `--skip-trivy`, `--skip-snyk`, `--skip-docker-scout`, `--skip-syft` *(skips SBOM)*, `--skip-grype`, `--skip-cosign`
* **Static Analysis (SAST):** `--skip-gitleaks`, `--skip-semgrep`, `--skip-bandit`, `--skip-r-audit` *(skips R checkers)*
* **Quality & Style Linters:** `--skip-flake8`, `--skip-black`, `--skip-nfcore-lint`
* **Validation Gates:** `--skip-nf-config`, `--skip-reproducibility`

### Zero-Configuration Cosign Key Mounting

When verifying cryptographic provenance, the framework automatically searches for a Cosign public key on your Mac host in this order of precedence:
1. Environment variable `COSIGN_PUBLIC_KEY`
2. Secret `.env` file parameter `COSIGN_PUBLIC_KEY`
3. Default path `~/.cosign/cosign.pub`
4. Current directory `cosign.pub`

If found, it is securely mounted as `/app/cosign.pub:ro` inside the container sandbox. The container's Cosign engine (**v3.0.6**) will then execute matching host-level signature verifications out-of-the-box.

### What happens at startup

```
========================================
🎯 Target pipeline:  /target
📁 Reports saved to: /app/reports/methylflow_2026-04-30_09-20
========================================
🐳 Auto-discovered 15 container images:
   • jd21/methylflow:1.1.0
   • jd21/methylflow-enrichment:1.1.0
   • jd21/methylflow-report:1.1.0
   • quay.io/biocontainers/multiqc:1.33--pyhdfd78af_0
   • ...
========================================
```

---

## 🔍 Security Checks

The suite runs **13 automated checks** across code quality, bioinformatic scripts security, container security, and supply chain integrity:

| #  | Check                    | Tool                  | What it does                                            |
|----|--------------------------|-----------------------|---------------------------------------------------------|
| 1  | Pipeline Linting         | `nf-core lint`        | Validates pipeline structure against nf-core standards  |
| 2  | Config Validation        | `nextflow config`     | Checks `nextflow.config` syntax and schema              |
| 3  | Static Code Analysis     | Semgrep               | Scans pipeline code for security anti-patterns          |
| 4  | Python Script SAST       | Bandit                | AST-level vulnerability scan for custom Python scripts  |
| 5  | Python Code Quality      | Flake8                | PEP 8 styling, syntax error, and undefined name linting |
| 6  | R Script SAST & SCA      | `lintr` + `oysteR`    | Dangerous R eval/system analysis and OSS Index SCA      |
| 7  | Container CVE Scan       | Trivy                 | Scans container images for known vulnerabilities        |
| 8  | Dependency Scan          | Snyk                  | Deep dependency analysis with CVSS scoring              |
| 9  | Docker Scout             | Docker Scout          | Docker-native CVE + recommendation engine               |
| 10 | SBOM + Vulnerability     | Syft + Grype          | Generates SBOM (SPDX) and scans for vulnerabilities     |
| 11 | Signature Verification   | Cosign                | Verifies container image signatures (Sigstore)          |
| 12 | Reproducibility Audit    | Custom                | Checks for `nextflow.lock` and pinned container digests |
| 13 | Provenance Tracking      | Custom                | Validates manifest definition and execution tracking    |

### Graceful Degradation
Every check is **optional**. If a tool isn't installed, the check is skipped with a `⚠️` warning and a `skipped` status in the JSON report. The remaining checks continue to run.

---

## 📁 Project Structure

```
nf-security-tools/
├── Dockerfile                  # Hardened Ubuntu 24.04 container with all tools
├── run_all_checks.sh           # Main orchestrator (entry point)
├── config/
│   └── config.env              # Thresholds, image names, scanner settings
├── scripts/
│   ├── run_nfcore_lint.sh      # nf-core lint
│   ├── validate_nextflow_config.sh
│   ├── run_semgrep.sh          # Semgrep static analysis
│   ├── run_bandit.sh           # Bandit Python SAST
│   ├── run_flake8.sh           # Flake8 Python linter
│   ├── run_r_audit.sh          # R lintr & oysteR security scan
│   ├── run_trivy.sh            # Trivy image scan
│   ├── run_snyk.sh             # Snyk container test
│   ├── run_docker_scout.sh     # Docker Scout CVE scan
│   ├── run_syft_grype.sh       # SBOM generation + Grype scan
│   ├── check_cosign.sh         # Cosign signature verification
│   ├── check_reproducibility.sh
│   ├── check_provenance.sh
│   ├── generate_report.sh      # Quarto HTML/PDF report generation
│   └── sign_images.sh          # Batch Cosign signing utility
├── report.qmd                  # Quarto report template
├── cosign.pub                  # Public key for signature verification
└── reports/                    # Generated reports (never in target dir)
    ├── methylflow_2026-04-30_08-45/
    │   ├── raw/                #   JSON outputs from each scanner
    │   └── final/              #   Rendered HTML report
    └── methylflow_2026-04-30_14-20/
        ├── raw/
        └── final/
```

---

## ⚙️ Configuration

All settings are in [`config/config.env`](config/config.env):

```bash
# CVSS threshold — fail any check if a vulnerability exceeds this score
CVSS_THRESHOLD=7.0

# Default container image to scan
CONTAINER_IMAGE="jd21/methylflow:1.1.0"

# Cosign public key for signature verification
COSIGN_PUBLIC_KEY="cosign.pub"

# Scanner severity thresholds
GRYPE_SEVERITY_THRESHOLD="high"
DOCKER_SCOUT_THRESHOLD="high"
```

> **Tip:** You can override `CONTAINER_IMAGE` from the command line without editing the config file:
> ```bash
> ./run_all_checks.sh ~/Projects/methylflow jd21/methylflow-enrich:1.1.0
> ```

---

## 🐳 Docker Container

The container is built on **Ubuntu 24.04 LTS** and includes all security tools pre-installed:

### Build

```bash
docker build -t jd21/nf-security-tools .
```

### Hardening Features

- **Base Image**: Ubuntu 24.04 LTS with `apt-get upgrade` for latest OS patches
- **No Go Compiler**: Cosign and Snyk are installed as pre-built binaries (not compiled from source), eliminating thousands of transitive Go dependencies
- **Python CVE Patches**: `setuptools` and `wheel` are force-upgraded to patch CVE-2025-47273 and CVE-2026-24049
- **Multi-Architecture**: Automatic detection of `amd64`/`arm64` for native performance on Apple Silicon and Linux

### Environment Variables

| Variable       | Description                              |
|----------------|------------------------------------------|
| `SNYK_TOKEN`   | Required for Snyk authentication         |
| `DOCKER_HOST`  | Set automatically when mounting Docker socket |

---

## 🔐 Image Signing

### Sign your images (batch)

```bash
# Edit scripts/sign_images.sh to list your images, then:
./scripts/sign_images.sh
```

The script automatically resolves each image tag to its **immutable SHA256 digest** before signing — this is the production-grade approach recommended by Sigstore.

### Verify a signature

```bash
cosign verify --key cosign.pub jd21/methylflow:1.1.0
```

A successful verification confirms:
- ✅ The image was signed by the holder of `cosign.key`
- ✅ The image contents have not been tampered with since signing
- ✅ The digest matches the exact bytes that were approved

---

## 📊 Reports

Reports are saved inside the **security suite directory** — never inside the target pipeline. Each run creates a unique, timestamped folder namespaced by the pipeline name:

```
nf-security-tools/reports/
├── methylflow_2026-04-30_08-45/     # First audit
│   ├── raw/                         # Individual JSON outputs
│   │   ├── trivy.json
│   │   ├── snyk.json
│   │   ├── grype.json
│   │   ├── semgrep.json
│   │   ├── cosign.json
│   │   ├── reproducibility.json
│   │   ├── provenance.json
│   │   └── ...
│   └── final/
│       └── report.html              # Aggregated HTML dashboard
├── methylflow_2026-04-30_14-20/     # Second audit (same day)
│   ├── raw/
│   └── final/
└── enrichment_2026-05-01_09-00/     # Different pipeline
    ├── raw/
    └── final/
```

> **Why?** This prevents accidental overwrites if the target pipeline already has a `reports/` directory (e.g., MultiQC, Nextflow traces). Your pipeline code is never modified by the security scanner.

---

## 🧪 Example Workflow

```bash
# 1. Build the security container
docker build -t jd21/nf-security-tools .

# 2. Run a full audit on your MethylFlow pipeline
docker run --rm -it \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v ~/Projects/methylflow:/target \
  -e SNYK_TOKEN=$SNYK_TOKEN \
  jd21/nf-security-tools \
  bash run_all_checks.sh /target jd21/methylflow:1.1.0

# 3. Check the reports
open ~/Projects/methylflow/reports/final/report.html

# 4. Sign your images after a clean audit
./scripts/sign_images.sh

# 5. Verify signatures
cosign verify --key cosign.pub jd21/methylflow:1.1.0
```

---

## 📋 Prerequisites

If running **without Docker**, ensure the following are installed:

| Tool        | Install Command                              |
|-------------|----------------------------------------------|
| Nextflow    | `curl -s https://get.nextflow.io \| bash`    |
| nf-core     | `pip install nf-core`                        |
| Trivy       | [trivy.dev](https://trivy.dev)               |
| Snyk        | [snyk.io](https://snyk.io/product/snyk-cli/) |
| Syft        | `curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \| sh` |
| Grype       | `curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \| sh` |
| Cosign      | [sigstore.dev](https://docs.sigstore.dev/cosign/system_config/installation/) |
| Semgrep     | `pip install semgrep`                        |
| Docker Scout| Built into Docker Desktop                    |
| jq          | `brew install jq` / `apt install jq`        |
| Quarto      | [quarto.org](https://quarto.org/docs/download/) |

> **Note:** All tools are **optional**. Missing tools are gracefully skipped.

---

## 📄 License

MIT

---

## 👤 Author

**Jyotirmoy Das**

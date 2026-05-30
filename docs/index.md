---
hide:
  - navigation
  - toc
---

# quindecagon: Clinical Security Framework

<div class="grid-container" markdown="1">

<div class="main-content" markdown="1">

Welcome to the official documentation for **quindecagon**—a comprehensive, containerized clinical-grade pipeline integrity, security assurance, and validation framework designed for <a href="https://www.cap.org/" target="_blank">CAP</a>/<a href="https://www.cms.gov/medicare/quality/clinical-laboratory-improvement-amendments" target="_blank">CLIA</a>/<a href="https://www.hhs.gov/hipaa/index.html" target="_blank">HIPAA</a>-regulated environments.

Unlike generic enterprise security tools which are blind to complex bioinformatics workflows, **quindecagon** sits directly at the intersection of data science, cryptography, and clinical governance. It synthesizes telemetries from **15 specialized defensive checkers** to guarantee the complete stability, reproducibility, and compliance of Nextflow genomic analysis pipelines.

## Key Framework Pillars

quindecagon is built around four fundamental security domains matching molecular pathology best-practices:

- **Pillar A: Software Supply Chain Verification**: Implements cryptographic signature checking (`Cosign`), Software Bill of Materials (SBOM) generation (`Syft`), and SCA vulnerability mapping (`Grype`, `Trivy`, `Snyk`, `Docker Scout`) to prevent dependency-chain hijacking and detect third-party library exposures.
- **Pillar B: Workflow Reproducibility**: Verifies locked Docker SHA image digests and pins channel tags to eliminate container drift and mathematically guarantee the end-to-end determinism of diagnostics runs.
- **Pillar C: Script SAST & Code Quality**: Audits custom Python data-processing helpers, Nextflow orchestrations, and R statistics code using static analysis linting engines (`Semgrep`, `Bandit`, `Flake8`, `lintr`, `riskmetric`) to flag insecure functions, memory leaks, and command-injection patterns before diagnostic runs.
- **Pillar D: Secrets Protection**: Runs local-first deep repository scanners (`Gitleaks`) to detect and block hardcoded API tokens, SSH keys, or server credentials in repository histories, protecting ePHI data vectors.

## Defensive Architecture Overview

quindecagon implements a hardened, layered security orchestration where check results are parsed in real-time, mapped to clinical laboratory accreditation checklist requirements, and evaluated through a dynamic compliance gatekeeper:

```mermaid
graph TD
    A[Nextflow Pipeline Target] --> B[quindecagon Auditing Gate]
    B --> C1[Pillar A: Supply Chain<br>Trivy, Snyk, Grype, Scout, Cosign, Syft]
    B --> C2[Pillar B: Reproducibility<br>Docker SHA Pinning, locks]
    B --> C3[Pillar C: Code SAST<br>Semgrep, Bandit, lintr, Flake8]
    B --> C4[Pillar D: Secrets Scan<br>Gitleaks History Detection]
    C1 --> D[Consensus Decision Engine]
    C2 --> D
    C3 --> D
    C4 --> D
    D --> E{4-Level Clinical Gate}
    E -->|100% Passed| F[APPROVED<br>Green Light for Production Diagnostics]
    E -->|1 Tool Failed| G[APPROVED WITH LIMITATIONS<br>Requires documented CAPA Plan]
    E -->|Domain Skips or Multiple Fails| H[WARNING<br>Urgent Director Review Required]
    E -->|Critical Vulnerabilities| I[FAILED / BLOCKED<br>Immediate Pipeline Suspension]
```

## Premium Visual Delivery

Every audit run deterministic compiles two highly aesthetic, readable compliance deliverables:

1.  **Quarto PDF Document**: A formal, typeset clinical certification report suitable for submitting to CAP/CLIA auditors, styled using tcolorbox matrices and complete regulatory citations.
2.  **HTML Interactive Cockpit**: A single-screen, modern, semi-transparent dashboard built with custom glassmorphic styling, containing a live dark-themed raw telemetry log explorer for forensic investigations.

## Credits

**quindecagon** was originally written by **Jyotirmoy Das** ([@JD2112](https://github.com/JD2112)) at the Bioinformatics Core Facility, BKV, Linköping University.

Maintenace is now lead by Jyotirmoy Das.

Main developer:

- [Jyotirmoy Das](https://github.com/JD2112)

## Acknowledgements

We thank the **Core Facility of Linköping University** and **Clinical Genomics Linköping, SciLifeLab** for their support.

</div>

<div class="side-panel" markdown="1">

![](images/quindecagon_logo.png)

## Run with

[![](https://img.shields.io/badge/Python-%E2%89%A53.8-blue?logo=python)](https://www.python.org/)
[![](https://img.shields.io/badge/Docker-supported-blue?logo=docker)](https://www.docker.com/)
[![](https://img.shields.io/badge/Nextflow-auditing-brightgreen)](https://www.nextflow.io/)
[![](https://img.shields.io/badge/Quarto-reports-blue)](https://quarto.org/)

## Stats

<div class="stats-grid">
  <div class="stats-item"><span id="gh-stars" class="stats-value">--</span><span class="stats-label">stars</span></div>
  <div class="stats-item"><span id="gh-issues" class="stats-value">--</span><span class="stats-label">open issues</span></div>
  <div class="stats-item"><span id="gh-last-release" class="stats-value">--</span><span class="stats-label">last release</span></div>
  <div class="stats-item"><span id="gh-last-update" class="stats-value">--</span><span class="stats-label">last update</span></div>
</div>

## Included Tools

<div class="tag-section">
  <a href="https://github.com/gitleaks/gitleaks" target="_blank"><img src="https://img.shields.io/badge/Gitleaks-security-blue?logo=github" alt="Gitleaks"></a>
  <a href="https://github.com/aquasecurity/trivy" target="_blank"><img src="https://img.shields.io/badge/Trivy-security-blue?logo=aquasecurity" alt="Trivy"></a>
  <a href="https://snyk.io/" target="_blank"><img src="https://img.shields.io/badge/Snyk-security-darkviolet?logo=snyk" alt="Snyk"></a>
  <a href="https://docs.docker.com/scout/" target="_blank"><img src="https://img.shields.io/badge/Docker_Scout-security-blue?logo=docker" alt="Docker Scout"></a>
  <a href="https://github.com/anchore/syft" target="_blank"><img src="https://img.shields.io/badge/Syft-SBOM-blue" alt="Syft"></a>
  <a href="https://github.com/anchore/grype" target="_blank"><img src="https://img.shields.io/badge/Grype-security-blue" alt="Grype"></a>
  <a href="https://github.com/sigstore/cosign" target="_blank"><img src="https://img.shields.io/badge/Cosign-supply_chain-blue" alt="Cosign"></a>
  <a href="https://semgrep.dev/" target="_blank"><img src="https://img.shields.io/badge/Semgrep-SAST-orange?logo=semgrep" alt="Semgrep"></a>
  <a href="https://github.com/PyCQA/bandit" target="_blank"><img src="https://img.shields.io/badge/Bandit-SAST-blue?logo=python" alt="Bandit"></a>
  <a href="https://flake8.pycqa.org/" target="_blank"><img src="https://img.shields.io/badge/Flake8-quality-blue?logo=python" alt="Flake8"></a>
  <a href="https://github.com/psf/black" target="_blank"><img src="https://img.shields.io/badge/Black-formatting-black?logo=python" alt="Black"></a>
  <a href="https://github.com/r-lib/lintr" target="_blank"><img src="https://img.shields.io/badge/lintr-quality-blue?logo=r" alt="lintr"></a>
  <a href="https://github.com/sonatype-nexus-community/oysteR" target="_blank"><img src="https://img.shields.io/badge/oysteR-dependency-blue?logo=r" alt="oysteR"></a>
  <a href="https://github.com/pharmar/riskmetric" target="_blank"><img src="https://img.shields.io/badge/riskmetric-risk-blue?logo=r" alt="riskmetric"></a>
  <a href="https://github.com/nf-core/tools" target="_blank"><img src="https://img.shields.io/badge/nf--core_lint-Nextflow-brightgreen?logo=nextflow" alt="nf-core lint"></a>
</div>

## Contributors

<div id="gh-contributors" class="contrib-grid">
  <!-- Dynamically populated from GitHub API -->
</div>

## Get Help

- [GitHub Issues](https://github.com/JD2112/milou/issues)

</div>

</div>

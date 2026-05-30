---
hide:
  - navigation
---

# Interactive Audit Outputs

**quindecagon** deterministic compiles two highly aesthetic, readable clinical compliance deliverables at the end of every pipeline verification run. These reports translate complex cryptographic and static telemetries into legally defensible audit records suitable for laboratory directors and regulatory inspectors.

---

## 1. Executive PDF Certification Report

Designed using professional LaTeX/Quarto typesetting engines, the **Quarto PDF Certificate** is a static, immutable, multi-page record suitable for submission to CAP/CLIA or ISO inspectors. It contains:

*   **Audit Timestamp & Session Digests:** Cryptographic fingerprinting of the analysis run to guarantee tamper-resistance.
*   **Executive Compliance Consensus:** High-visibility consensus tags detailing whether the pipeline is approved, conditionally approved, or blocked.
*   **Detailed Pillar Assessments:** Section-by-section breakdown of every check result mapped to its specific CAP MOM checklist and HIPAA standard numbers.
*   **Sign-Off Block:** Formal clinical lab director review signature fields to document CAPA compliance or overrides.

---

## 2. HTML Compliance Cockpit Dashboard (Live Demo)

The **Interactive HTML Cockpit** is a single-screen, modern, responsive portal. It is styled with custom glassmorphism and is built to serve as a fast developer/compliance dashboard. 

Below is the live telemetry layout matching the actual clinical audit log from the latest **TwistNext** methylation pipeline validation run:

### Session & Consent Executive Summary

| Target Nextflow Pipeline | Overall Audit Consensus | Generated Time | Clinical Scope |
| :--- | :--- | :--- | :--- |
| `TwistNext / methylflow` | <span class="status-pill warning">Warning</span> | May 26, 2026 at 09:57:50 | Rare Disease & Cancer Diagnostic |

### Dynamic Metrics Summary

*   **SBOM Generation:** `0 / 9` (FDA Compliance Check)
*   **Cosign Signatures:** `0 / 9` (Supply Chain Security)
*   **Critical CVEs:** `21` (Trivy OS Vulnerabilities)
*   **Active Secrets:** `3` (Gitleaks Exposure)

---

### Telemetry Tab A: Container Infrastructure Matrix

This matrix synthesizes OS-level layers and package vulnerability scans in a robust consensus matrix (CAP MOM.36150 / MOM.36200).

| Container Image Target | Trivy (C/H) | Scout (C/H) | SBOM Manifest | Signature (Cosign) | Top CVE Traces Identified |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `quay.io/biocontainers/multiqc/sha256:dfd9fde2` | <span style="color:#c62828; font-weight:bold;">14</span> / <span style="color:#e65100; font-weight:bold;">50</span> | `0` / `0` | <span class="status-pill failed-blocked">Missing</span> | <span class="status-pill failed-blocked">Unsigned</span> | • CVE-2025-68973 (gpgv)<br>• CVE-2026-4878 (libcap2)<br>• CVE-2026-40393 (libegl-mesa0) |
| `jd21/methylflow-main/sha256:fb1053ea` | <span style="color:#c62828; font-weight:bold;">3</span> / <span style="color:#e65100; font-weight:bold;">15</span> | `0` / `0` | <span class="status-pill failed-blocked">Missing</span> | <span class="status-pill failed-blocked">Unsigned</span> | • CVE-2026-4878 (libcap2)<br>• CVE-2026-33845 (libgnutls30)<br>• CVE-2026-42010 (libgnutls30) |
| `jd21/methylflow-unified/sha256:22fa9293` | <span style="color:#c62828; font-weight:bold;">3</span> / <span style="color:#e65100; font-weight:bold;">12</span> | `0` / `0` | <span class="status-pill failed-blocked">Missing</span> | <span class="status-pill failed-blocked">Unsigned</span> | • CVE-2026-4878 (libcap2)<br>• CVE-2026-33845 (libgnutls30)<br>• CVE-2026-42010 (libgnutls30) |
| `pegi3s/qualimap/sha256:2b0220e5` | <span style="color:#c62828; font-weight:bold;">1</span> / <span style="color:#e65100; font-weight:bold;">44</span> | `0` / `0` | <span class="status-pill failed-blocked">Missing</span> | <span class="status-pill failed-blocked">Unsigned</span> | • CVE-2022-25235 (libexpat1)<br>• CVE-2022-25236 (libexpat1)<br>• CVE-2022-3515 (libksba8) |
| `jd21/milou-enrich/sha256:670ba39d` | `0` / <span style="color:#e65100; font-weight:bold;">61</span> | `0` / `0` | <span class="status-pill failed-blocked">Missing</span> | <span class="status-pill failed-blocked">Unsigned</span> | • CVE-2022-36402 (linux-libc-dev)<br>• CVE-2023-21400 (linux-libc-dev)<br>• CVE-2023-52620 (linux-libc-dev) |
| `quay.io/biocontainers/bioconductor-dss:57f5` | `0` / <span style="color:#e65100; font-weight:bold;">3</span> | `0` / `0` | <span class="status-pill failed-blocked">Missing</span> | <span class="status-pill failed-blocked">Unsigned</span> | • CVE-2026-23949 (jaraco.context)<br>• CVE-2025-47273 (setuptools)<br>• CVE-2026-24049 (wheel) |
| `quay.io/biocontainers/bioconductor-gviz:03ee2` | `0` / `0` | `0` / `0` | <span class="status-pill failed-blocked">Missing</span> | <span class="status-pill failed-blocked">Unsigned</span> | _None (Clean container baseline)_ |
| `quay.io/biocontainers/bioconductor-pathview:4f53` | `0` / `0` | `0` / `0` | <span class="status-pill failed-blocked">Missing</span> | <span class="status-pill failed-blocked">Unsigned</span> | _None (Clean container baseline)_ |
| `jd21/milou/report/sha256:1403e4d4` | `0` / `0` | `0` / `0` | <span class="status-pill failed-blocked">Missing</span> | <span class="status-pill failed-blocked">Unsigned</span> | _None (Clean container baseline)_ |

---

### Telemetry Tab B: Hardcoded Secrets Detail

Traces credentials leaks inside repo history to prevent database/HIPAA breaches (HIPAA §164.308 / CAP MOM.36100).

| Leaked Source File | Line Number | Gitleaks Scan Rule Match & Risk Summary |
| :--- | :--- | :--- |
| `containers/docker/COSIGN_SIGNING_GUIDE.md` | `74` | Identified a hardcoded HashiCorp Terraform password field, risking unauthorized infrastructure configuration. |
| `containers/docker/COSIGN_SIGNING_GUIDE.md` | `140` | Identified a hardcoded AWS SSH key block, posing credentials bypass risks for host servers. |
| `containers/docker/COSIGN_SIGNING_GUIDE.md` | `154` | Identified a hardcoded GitLab pipeline token, risking downstream CI/CD hijacking. |

---

### Telemetry Tab C: Source Code SAST & Quality Checks

Reports active coding anti-patterns, command injections, and scoping irregularities (CAP MOM.36050).

| Scan Engine | File Path & Target Reference | Anti-Pattern & Security Trace Message |
| :--- | :--- | :--- |
| **Black** (Python) | `Python Files: N/A` | `Black` found 5 unformatted Python helper scripts. Format checking failed. |
| **lintr** (R) | `/target/bin/annotate_results.R:9` | Indentation should be 2 spaces but is 4 spaces. |
| **lintr** (R) | `/target/bin/annotate_results.R:10` | Could not find exported symbols for package "edgeR" in search path. |
| **Bandit** (Python) | `/target/bin/parse_telemetry.py:42` | Use of insecure `eval()` detected. High risk of command injection. |
| **Semgrep** (Groovy) | `/target/workflows/methylflow.nf:128` | Dangerous bash interpolation inside Nextflow script execution block. |

---

### Actionable Deficiencies Summary

Based on these telemetry streams, the compliance gatekeeper logs the following deficiencies in the cockpit dashboard:

> [!WARNING]
> **Clinical Compliance Alert:**
>
> *   **Systemic Supply Chain Vulnerability (Domain A Failed):** 5 container images failed verification due to missing Software Bill of Materials (SBOM) generation (`Syft`) and Cryptographic Signatures (`Cosign`).
> *   **Critical Secrets Exposure (Domain D Passed with Deficiencies):** 3 active secrets (AWS keys, pipeline tokens, database passwords) detected in git history.
> *   **Code Quality (Domain C Skipped/Limitation):** Styling, syntax, and formatting checker issues identified.
> *   **Action Required:** Rebuild the pipeline target using the `--skip` controls strictly or complete the CAPA action plan within 30 days to obtain authorized production status.

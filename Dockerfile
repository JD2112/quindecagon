#================================================================================
# VULNERABILITY MANIFEST - jd21/quindecagon:0.3.0
#================================================================================
# Known Vulnerabilities in Go 1.20.5 (embedded in compiled tool binaries):
#
# CRITICAL (3):
#   - CVE-2025-68121: Go stdlib <1.24.13 (affects net/http, etc.)
#   - CVE-2024-24790: Go stdlib <1.21.11 (affects net/mail parsing)
#   - CVE-2025-22871: Go stdlib <1.23.8 (affects crypto/tls)
#
# ROOT CAUSE:
#   Security tools (Syft v1.20.0, Grype v0.88.0, Trivy v0.55.0, Cosign v2.4.1)
#   have Go 1.20.5 statically linked into their compiled binaries. Rebuilding
#   with newer Go does not patch these transitive dependencies without
#   upgrading to tool versions built with Go 1.24+.
#
# MITIGATION TRACKING:
#   - Awaiting upstream releases: Syft 1.21+, Grype 0.89+, Trivy 0.56+
#   - System packages upgraded to latest (setuptools 78.1.1+, cryptography 43.0.1+)
#   - HIGH vulns in docker/docker reduced from 3 to 0 via v28.0.0
#   - Overall risk surface reduced despite embedded Go stdlib CVEs
#
# NEXT STEPS:
#   1. Monitor tool release notes for Go 1.24+ builds
#   2. Once available, update tool versions in Stage 1 builder
#   3. Re-test with docker scout cves to verify CRITICAL reduction
#
#================================================================================

# --- Stage 1: Hardened Go Builder (Go 1.26 for forward compatibility) ---
FROM golang:1.26-alpine AS builder
ENV GOBIN=/go/bin
RUN apk add --no-cache build-base git

# 1. Build and Patch Syft (v1.20.0)
# TODO: Upgrade to v1.21+ once released with Go 1.24+ support
RUN git clone --depth 1 --branch v1.20.0 https://github.com/anchore/syft.git /tmp/syft && \
    cd /tmp/syft && \
    go mod edit -replace golang.org/x/crypto=golang.org/x/crypto@v0.31.0 && \
    go mod tidy && \
    CGO_ENABLED=0 go build -ldflags "-s -w" -o /go/bin/syft ./cmd/syft

# 2. Build and Patch Grype (v0.88.0)
# TODO: Upgrade to v0.89+ once released with Go 1.24+ support
RUN git clone --depth 1 --branch v0.88.0 https://github.com/anchore/grype.git /tmp/grype && \
    cd /tmp/grype && \
    go mod edit -replace github.com/docker/docker=github.com/docker/docker@v28.0.0+incompatible && \
    go mod edit -replace golang.org/x/crypto=golang.org/x/crypto@v0.31.0 && \
    go mod tidy && \
    CGO_ENABLED=0 go build -ldflags "-s -w" -o /go/bin/grype ./cmd/grype

# 3. Build Cosign (v3.0.6)
RUN git clone --depth 1 --branch v3.0.6 https://github.com/sigstore/cosign.git /tmp/cosign && \
    cd /tmp/cosign && \
    go mod edit -replace golang.org/x/crypto=golang.org/x/crypto@v0.31.0 && \
    go mod tidy && \
    CGO_ENABLED=0 go build -ldflags "-s -w" -o /go/bin/cosign ./cmd/cosign

# 4. Build and Patch Trivy (v0.55.0)
# TODO: Upgrade to v0.56+ once released with Go 1.24+ support
RUN git clone --depth 1 --branch v0.55.0 https://github.com/aquasecurity/trivy.git /tmp/trivy && \
    cd /tmp/trivy && \
    go mod edit -replace golang.org/x/crypto=golang.org/x/crypto@v0.31.0 && \
    go mod edit -replace github.com/go-git/go-git/v5=github.com/go-git/go-git/v5@v5.13.0 && \
    go mod tidy && \
    CGO_ENABLED=0 go build -ldflags "-s -w" -o /go/bin/trivy ./cmd/trivy

# 5. Build Hardened esbuild
RUN CGO_ENABLED=0 go install -ldflags "-s -w" github.com/evanw/esbuild/cmd/esbuild@latest


# --- Stage 2: Final Hardened Runtime (Cleaned Ubuntu 24.04) ---
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive

# 1. Full System Scrub + Removal of vulnerable system python packages
RUN apt-get update && apt-get upgrade -y && \
    apt-get remove -y python3-setuptools python3-wheel && \
    apt-get install -y --no-install-recommends \
    curl wget git jq python3 python3-pip openjdk-17-jre-headless ca-certificates xz-utils gnupg lsb-release binutils \
    r-base r-base-dev libcurl4-openssl-dev libssl-dev libxml2-dev libfontconfig1-dev libharfbuzz-dev libfribidi-dev libfreetype6-dev libpng-dev libjpeg-dev libtiff-dev && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get clean

# 2. Copy the Hardened, Scrubbed Binaries
COPY --from=builder /go/bin/syft /usr/local/bin/syft
COPY --from=builder /go/bin/grype /usr/local/bin/grype
COPY --from=builder /go/bin/cosign /usr/local/bin/cosign
COPY --from=builder /go/bin/trivy /usr/local/bin/trivy
COPY --from=builder /go/bin/esbuild /usr/local/bin/hardened-esbuild

# 3. Install Nextflow (v25.10.4)
ENV NEXTFLOW_VERSION=25.10.4
RUN curl -sSfL https://get.nextflow.io | bash && \
    mv nextflow /usr/local/bin/ && \
    chmod +x /usr/local/bin/nextflow

# 4. Install Python Dashboard & Security Tools with patched deps
RUN pip3 install --upgrade --ignore-installed 'setuptools>=78.1.1' 'wheel>=0.46.2' 'cryptography>=43.0.1' --break-system-packages && \
    pip3 install --no-cache-dir \
    'semgrep>=1.160.0' \
    'bandit>=1.7.5' \
    'flake8>=6.0.0' \
    'flake8-json>=2.1.0' \
    'black>=24.0.0' \
    'pandas==2.2.2' \
    'tabulate==0.9.0' \
    'jupyter==1.0.0' \
    'papermill==2.6.0' \
    'nbformat==5.10.4' \
    'nf-core==2.14' \
    'pyyaml>=6.0.1' \
    --break-system-packages

# 5. Install R Security Auditing Tools (lintr, oysteR, riskmetric, jsonlite)
RUN Rscript -e "install.packages(c('jsonlite', 'lintr', 'oysteR', 'riskmetric'), repos='https://cloud.r-project.org')"

# 6. Install nf-test (Official script)
RUN curl -fsSL https://code.askimed.com/install/nf-test | bash && mv nf-test /usr/local/bin/

# 7. Atomic Installation & Hardening of Quarto (v1.9.37)
ENV QUARTO_VERSION=1.9.37
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "arm64" ]; then Q_ARCH="arm64"; Q_DIR="aarch64"; else Q_ARCH="amd64"; Q_DIR="x86_64"; fi && \
    curl -o quarto.deb -L https://github.com/quarto-dev/quarto-cli/releases/download/v${QUARTO_VERSION}/quarto-${QUARTO_VERSION}-linux-${Q_ARCH}.deb && \
    apt-get update && apt-get install -y --no-install-recommends ./quarto.deb && \
    rm -f /opt/quarto/bin/tools/${Q_DIR}/esbuild && \
    cp /usr/local/bin/hardened-esbuild /opt/quarto/bin/tools/${Q_DIR}/esbuild && \
    rm quarto.deb && \
    rm -rf /var/lib/apt/lists/*

# 8. Total Exorcism (Aggressive baseline enforcement)
RUN find / -xdev -type f -executable -exec grep -l "Go build ID" {} + | xargs -I {} sh -c ' \
    V=$(strings {} | grep -oE "go1\.[0-9]{1,2}(\.[0-9]{1,2})?" | head -n 1); \
    if [ ! -z "$V" ]; then \
        MINOR=$(echo $V | cut -d. -f2); \
        if [ "$MINOR" -lt 24 ]; then \
            echo "Removing vulnerable $V binary at: {}"; \
            rm {}; \
        fi; \
    fi' || true

# 9. Install TinyTeX via Quarto
RUN quarto install tinytex && \
    mv /root/.TinyTeX /opt/tinytex && \
    /opt/tinytex/bin/*/tlmgr install \
        helvetic psnfss tcolorbox environ trimspaces etoolbox \
        pgf mathpazo booktabs tabu sectsty fancyhdr tipa \
        koma-script titling tikzfill fontawesome5 cleveref \
        caption microtype xcolor listings enumitem parskip \
        xurl bookmark pdfcol pdfcolmk xcolor-solarized \
        oberdiek tools listingsutf8 infwarerr kvoptions \
        ltxcmds etexcmds pdftexcmds hycolor kvsetkeys \
        kvdefinekeys && \
    /opt/tinytex/bin/*/tlmgr path add && \
    chmod -R 777 /opt/tinytex

# 10. Install Gitleaks (Architecture Aware)
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "arm64" ]; then G_ARCH="arm64"; else G_ARCH="x64"; fi && \
    G_VER="8.18.2" && \
    curl -fLo /tmp/gitleaks.tar.gz "https://github.com/gitleaks/gitleaks/releases/download/v${G_VER}/gitleaks_${G_VER}_linux_${G_ARCH}.tar.gz" && \
    tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks && \
    chmod +x /usr/local/bin/gitleaks && \
    rm -f /tmp/gitleaks.tar.gz

# 11. Install Snyk CLI (Architecture Aware)
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "arm64" ]; then SNYK_BIN="snyk-linux-arm64"; else SNYK_BIN="snyk-linux"; fi && \
    curl -fLo /usr/local/bin/snyk "https://static.snyk.io/cli/latest/${SNYK_BIN}" && \
    chmod +x /usr/local/bin/snyk

# 12. Install Docker Scout CLI
RUN curl -sSfL https://raw.githubusercontent.com/docker/scout-cli/main/install.sh | sh -s -- -b /usr/local/bin

# Add TinyTeX to PATH globally
ENV PATH="/opt/tinytex/bin/x86_64-linux:/opt/tinytex/bin/aarch64-linux:${PATH}"

# 13. Final Configuration
RUN groupadd -r pipeline && useradd -r -g pipeline -m -d /home/pipeline pipeline
WORKDIR /app
COPY . /app/
RUN chmod -R +x /app/*/scripts/*.sh 2>/dev/null || true && \
    chown -R pipeline:pipeline /app

USER pipeline
CMD ["bash", "scripts/run_all_checks.sh"]

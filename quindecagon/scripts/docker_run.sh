#!/bin/bash

VERSION="0.3.1"
DIGEST=""

if [ -n "$DIGEST" ]; then
    IMAGE_NAME="jd21/quindecagon@$DIGEST"
else
    IMAGE_NAME="jd21/quindecagon:$VERSION"
fi

# Capture host run command for pipeline traceability
export AUDIT_RUN_COMMAND="./$(basename "$0") $@"

# --- Path Handling ---
# SCRIPT_DIR: quindecagon/scripts
# PKG_DIR:    quindecagon
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PKG_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Find Dockerfile and resolve correct build context
if [ -f "$PKG_DIR/docker/Dockerfile" ]; then
    DOCKERFILE="$PKG_DIR/docker/Dockerfile"
    BUILD_CONTEXT="$PKG_DIR"
else
    DOCKERFILE="$PKG_DIR/../Dockerfile"
    BUILD_CONTEXT="$PKG_DIR/.."
fi

# Find .env and Reports (default to CWD if not in parent of package)
# This allows 'pip install' to work while keeping development working
CWD="$(pwd)"
if [ -f "$PKG_DIR/../.env" ]; then
    ENV_FILE="$PKG_DIR/../.env"
    REPORTS_DIR="$PKG_DIR/../reports"
else
    ENV_FILE="$CWD/.env"
    REPORTS_DIR="$CWD/reports"
fi

mkdir -p "$REPORTS_DIR"

if docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
    echo "✅ Docker image $IMAGE_NAME is already available locally."
else
    echo "🔍 Image $IMAGE_NAME not found locally. Attempting to pull from Docker Hub..."
    if docker pull "$IMAGE_NAME"; then
        echo "✅ Successfully pulled $IMAGE_NAME from Docker Hub."
    else
        echo "⚠️  Could not pull image. Falling back to local build (this may take a while)..."
        echo "Building Docker image jd21/quindecagon:$VERSION..."
        # Build context is dynamically resolved so it can see all bundled files
        docker build --no-cache -t "jd21/quindecagon:$VERSION" -f "$DOCKERFILE" "$BUILD_CONTEXT"
        if [ $? -eq 0 ]; then
            IMAGE_NAME="jd21/quindecagon:$VERSION"
            echo "🧹 Cleaning up old versions of jd21/quindecagon to save space..."
            NEW_ID=$(docker images -q "$IMAGE_NAME")
            docker images jd21/quindecagon -q | grep -v "$NEW_ID" | xargs docker rmi 2>/dev/null || true
        fi
    fi
fi
# --- Argument Handling ---
TARGET_DIR=""
# Loop through arguments to handle flags
while [[ $# -gt 0 ]]; do
    case "$1" in
        --env-file)
            ENV_FILE="$2"
            shift 2
            ;;
        --skip-snyk)
            SKIP_SNYK="true"
            shift
            ;;
        --skip-gitleaks)
            SKIP_GITLEAKS="true"
            shift
            ;;
        --skip-trivy)
            SKIP_TRIVY="true"
            shift
            ;;
        --skip-docker-scout)
            SKIP_DOCKER_SCOUT="true"
            shift
            ;;
        --skip-syft)
            SKIP_SYFT="true"
            shift
            ;;
        --skip-grype)
            SKIP_GRYPE="true"
            shift
            ;;
        --skip-cosign)
            SKIP_COSIGN="true"
            shift
            ;;
        --skip-semgrep)
            SKIP_SEMGREP="true"
            shift
            ;;
        --skip-bandit)
            SKIP_BANDIT="true"
            shift
            ;;
        --skip-flake8)
            SKIP_FLAKE8="true"
            shift
            ;;
        --skip-black)
            SKIP_BLACK="true"
            shift
            ;;
        --skip-r-audit)
            SKIP_R_AUDIT="true"
            shift
            ;;
        --skip-nfcore-lint)
            SKIP_NFCORE_LINT="true"
            shift
            ;;
        --skip-nf-config)
            SKIP_NF_CONFIG="true"
            shift
            ;;
        --skip-reproducibility)
            SKIP_REPRODUCIBILITY="true"
            shift
            ;;
        *)
            TARGET_DIR="$1"
            shift
            ;;
    esac
done

if [ -z "$TARGET_DIR" ]; then
    echo "ℹ️  No pipeline directory provided on the command line."
    read -e -p "📁 Please enter the path to the Nextflow pipeline directory to audit: " INPUT_DIR
    if [ -z "$INPUT_DIR" ]; then
        echo "❌ Audit cancelled: No directory specified."
        exit 1
    fi
    TARGET_DIR="${INPUT_DIR/#\~/$HOME}"
fi

# Resolve to absolute paths
TARGET_DIR="$(cd "$TARGET_DIR" 2>/dev/null && pwd)"
if [ -z "$TARGET_DIR" ] || [ ! -d "$TARGET_DIR" ]; then
    echo "❌ Error: Specified directory does not exist or could not be accessed."
    exit 1
fi

if [[ "$ENV_FILE" != /* ]]; then
    ENV_FILE="$CWD/$ENV_FILE"
fi

# --- Locate and Mount Cosign Public Key if present ---
HOST_COSIGN_KEY=""
if [ -n "$COSIGN_PUBLIC_KEY" ]; then
    HOST_COSIGN_KEY="$COSIGN_PUBLIC_KEY"
elif [ -f "$ENV_FILE" ]; then
    HOST_COSIGN_KEY=$(grep -E "^COSIGN_PUBLIC_KEY=" "$ENV_FILE" | cut -d= -f2- | tr -d '"' | tr -d "'")
fi

HOST_COSIGN_KEY="${HOST_COSIGN_KEY/#\~/$HOME}"

COSIGN_KEY_MOUNT_ARGS=()
if [ -n "$HOST_COSIGN_KEY" ] && [ -f "$HOST_COSIGN_KEY" ]; then
    COSIGN_KEY_MOUNT_ARGS=(-v "$HOST_COSIGN_KEY:/app/cosign.pub:ro")
    echo "🔑 Mounted custom Cosign public key: $HOST_COSIGN_KEY"
elif [ -f "$HOME/.cosign/cosign.pub" ]; then
    COSIGN_KEY_MOUNT_ARGS=(-v "$HOME/.cosign/cosign.pub:/app/cosign.pub:ro")
    echo "🔑 Mounted default Cosign public key from ~/.cosign/cosign.pub"
elif [ -f "$CWD/cosign.pub" ]; then
    COSIGN_KEY_MOUNT_ARGS=(-v "$CWD/cosign.pub:/app/cosign.pub:ro")
    echo "🔑 Mounted default Cosign public key from current directory"
else
    echo "⚠️  No Cosign public key found on host. Cosign signature checks will run in keyless fallback mode."
fi

# --- Docker Socket GID Detection for Non-Root Container Access ---
# Detect socket GID inside the container namespace to handle host vs container VM GID mismatches
CONTAINER_DOCKER_GID=$(docker run --rm -v /var/run/docker.sock:/var/run/docker.sock "$IMAGE_NAME" stat -c '%g' /var/run/docker.sock 2>/dev/null || \
                       docker run --rm -v /var/run/docker.sock:/var/run/docker.sock "$IMAGE_NAME" stat -f '%g' /var/run/docker.sock 2>/dev/null)

DOCKER_GROUP_ARGS=()
if [ -n "$CONTAINER_DOCKER_GID" ]; then
    DOCKER_GROUP_ARGS=(--group-add "$CONTAINER_DOCKER_GID")
    echo "🐳 Detected container-namespace Docker socket GID: $CONTAINER_DOCKER_GID (granted socket access inside container)"
else
    # Fallback to host GID detection
    HOST_DOCKER_GID=$(stat -f '%g' /var/run/docker.sock 2>/dev/null || stat -c '%g' /var/run/docker.sock 2>/dev/null)
    if [ -n "$HOST_DOCKER_GID" ]; then
        DOCKER_GROUP_ARGS=(--group-add "$HOST_DOCKER_GID")
        echo "🐳 Detected host Docker socket GID: $HOST_DOCKER_GID (granted socket access inside container)"
    fi
fi

read -p "Press [Enter] key to continue..."

docker run --rm -it \
  -v "/var/run/docker.sock:/var/run/docker.sock" \
  "${DOCKER_GROUP_ARGS[@]}" \
  -v "$TARGET_DIR:/target:ro" \
  -v "$REPORTS_DIR:/app/reports" \
  -v "$PKG_DIR/report.qmd:/app/report.qmd" \
  -v "$PKG_DIR/scripts:/app/scripts" \
  -v "$PKG_DIR/config:/app/config:ro" \
  "${COSIGN_KEY_MOUNT_ARGS[@]}" \
  --env-file "$ENV_FILE" \
  --env "TEXMFVAR=/tmp/texmf-var" \
  --env "TEXMFCACHE=/tmp/texmf-cache" \
  --env "XDG_CACHE_HOME=/tmp/xdg-cache" \
  --env "HOME=/tmp" \
  --env "SKIP_SNYK=${SKIP_SNYK:-false}" \
  --env "SKIP_GITLEAKS=${SKIP_GITLEAKS:-false}" \
  --env "SKIP_TRIVY=${SKIP_TRIVY:-false}" \
  --env "SKIP_DOCKER_SCOUT=${SKIP_DOCKER_SCOUT:-false}" \
  --env "SKIP_SYFT=${SKIP_SYFT:-false}" \
  --env "SKIP_GRYPE=${SKIP_GRYPE:-false}" \
  --env "SKIP_COSIGN=${SKIP_COSIGN:-false}" \
  --env "SKIP_SEMGREP=${SKIP_SEMGREP:-false}" \
  --env "SKIP_BANDIT=${SKIP_BANDIT:-false}" \
  --env "SKIP_FLAKE8=${SKIP_FLAKE8:-false}" \
  --env "SKIP_BLACK=${SKIP_BLACK:-false}" \
  --env "SKIP_R_AUDIT=${SKIP_R_AUDIT:-false}" \
  --env "SKIP_NFCORE_LINT=${SKIP_NFCORE_LINT:-false}" \
  --env "SKIP_NF_CONFIG=${SKIP_NF_CONFIG:-false}" \
  --env "SKIP_REPRODUCIBILITY=${SKIP_REPRODUCIBILITY:-false}" \
  --env "PIPELINE_NAME=$(basename "$TARGET_DIR")" \
  --env "PIPELINE_PATH=$TARGET_DIR" \
  --env "COSIGN_PUBLIC_KEY=/app/cosign.pub" \
  --env "AUDIT_RUN_COMMAND=${AUDIT_RUN_COMMAND}" \
  "$IMAGE_NAME" \
  bash scripts/run_all_checks.sh /target

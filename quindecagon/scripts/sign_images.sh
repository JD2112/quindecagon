#!/bin/bash

# List of images to sign
IMAGES=(
    "jd21/methylflow-report:1.1.0"
    "jd21/methylflow-enrich:1.1.0"
    "jd21/methylflow-unified:1.1.0"
    "jd21/methylflow:1.1.0"
)

# 1. Check for cosign keys
if [ ! -f "cosign.key" ]; then
    echo "🔑 No cosign.key found. Generating a new key pair..."
    cosign generate-key-pair
fi

# 2. Sign each image by its DIGEST
for IMG_TAG in "${IMAGES[@]}"; do
    echo "--------------------------------------"
    echo "🔍 Fetching digest for: $IMG_TAG"
    
    # Get the unique SHA256 digest from Docker Hub
    # We use jq to parse the manifest and handle both single and multi-arch images
    DIGEST=$(docker manifest inspect "$IMG_TAG" | jq -r '.config.digest // .manifests[0].digest')
    
    if [ -z "$DIGEST" ] || [ "$DIGEST" == "null" ]; then
        echo "❌ Error: Could not find digest for $IMG_TAG. Skipping..."
        continue
    fi

    # Construct the immutable reference: repo@sha256:digest
    REPO=$(echo "$IMG_TAG" | cut -d: -f1)
    IMMUTABLE_REF="${REPO}@${DIGEST}"

    echo "✍️  Signing immutable reference: $IMMUTABLE_REF"
    cosign sign --key cosign.key "$IMMUTABLE_REF"
done

echo "--------------------------------------"
echo "✅ Immutable batch signing complete!"

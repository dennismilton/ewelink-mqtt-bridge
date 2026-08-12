#!/usr/bin/env bash
# Build arm64 on the Mac and push to the registry (same model as vfc).
set -euo pipefail
IMAGE="${IMAGE:-dmtamsen/privhub:maracaibo-sonoff}"
docker buildx build --platform linux/arm64 -t "$IMAGE" --push .
echo "pushed $IMAGE"

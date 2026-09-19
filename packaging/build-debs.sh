#!/bin/bash
# Build locally using exactly the same containers as the release workflow.
set -euo pipefail
cd "$(dirname "$0")/.."

targets=(debian12 debian13 ubuntu22.04 ubuntu24.04 ubuntu26.04)
case "${1:-all}" in
  -h|--help)
    echo "Usage: $0 [all|debian12|debian13|ubuntu22.04|ubuntu24.04|ubuntu26.04]"
    echo 'Packages and SHA256SUMS are written to dist/<distribution>/.'
    exit 0
    ;;
  all) ;;
  debian12|debian13|ubuntu22.04|ubuntu24.04|ubuntu26.04) targets=("$1") ;;
  *) echo "Unknown distribution: $1 (see --help)" >&2; exit 1 ;;
esac
if (( $# > 1 )); then
  echo 'Expected at most one distribution argument (see --help)' >&2
  exit 1
fi

# Use the source commit time for the Debian changelog and archive timestamps.
source_epoch=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}
for distribution in "${targets[@]}"; do
  case "$distribution" in
    debian12) base_image=debian:12-slim ;;
    debian13) base_image=debian:13-slim ;;
    ubuntu22.04) base_image=ubuntu:22.04 ;;
    ubuntu24.04) base_image=ubuntu:24.04 ;;
    ubuntu26.04) base_image=ubuntu:26.04 ;;
  esac
  docker buildx build --platform linux/amd64 --progress plain \
    --file packaging/Dockerfile \
    --build-arg "BASE_IMAGE=$base_image" \
    --build-arg "SOURCE_DATE_EPOCH=$source_epoch" \
    --build-arg "RELEASE_TAG=${UBGP_RELEASE_TAG:-}" \
    --output "type=local,dest=dist/$distribution" .
done

#!/usr/bin/env bash
# cross-compile-binary.sh, Build Bao for the specified GOOS/GOARCH
# Expects GOOS/GOARCH (and optional GOARM) in the environment.
set -euo pipefail

if [[ -z "${GOOS:-}" || -z "${GOARCH:-}" ]]; then
  echo "GOOS/GOARCH must be set" >&2
  exit 1
fi

# Determine output filename
EXT=""
if [[ "$GOOS" == "windows" ]]; then
  EXT=".exe"
fi
BIN="bao-${GOOS}-${GOARCH}${EXT}"

# Clear any previous build artifacts for cleanliness
rm -f "${BIN}"

# Disable CGO for cross-compilation unless explicitly enabled
export CGO_ENABLED="${CGO_ENABLED:-0}"

# Respect BUILD_TAGS if the workflow/front-end set them; default to empty
export BUILD_TAGS="${BUILD_TAGS:-}"

PKG="github.com/openbao/openbao"
GIT_COMMIT=$(git rev-parse --short=12 HEAD || echo "unknown")
BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
LD_FLAGS="-s -w -X ${PKG}/version.GitCommit=${GIT_COMMIT} -X ${PKG}/version.BuildDate=${BUILD_DATE}"

echo "Cross-compiling bao for $GOOS/$GOARCH (CGO_ENABLED=$CGO_ENABLED)"
GOOS=$GOOS GOARCH=$GOARCH GOARM=${GOARM:-} \
  go build -trimpath -ldflags="$LD_FLAGS" -tags "${BUILD_TAGS:-openbao}" -o "$BIN" .

echo "Built $BIN"

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  echo "out=$BIN" >> "$GITHUB_OUTPUT"
fi
#!/usr/bin/env bash

# This script downloads release artifacts for the given release version
# matching the given pattern into dist/ and verifies their checksums and cosign
# signatures.
#
# For example:
# $ VERSION=v2.6.0 PATTERN=*.deb ./scripts/release/download-artifacts.sh
#
# Checksums and signatures are removed from the filesystem post-verification.

set -euo pipefail

GITHUB_REPOSITORY=${GITHUB_REPOSITORY:-openbao/openbao}

mkdir -p dist && cd dist

gh release download \
  --repo="$GITHUB_REPOSITORY" \
  --pattern="$PATTERN" \
  --pattern="$PATTERN.sigstore.json" \
  --pattern=checksums.txt \
  --pattern=checksums.txt.sigstore.json \
  "$VERSION" "$@"

for f in $PATTERN; do
    echo "Verifying $f via checksum..."
    awk -v f="$f" '$2 == f' checksums.txt | sha256sum -c -
done

for f in checksums.txt $PATTERN; do
    echo "Verifying $f via cosign..."
    cosign verify-blob \
        --bundle="$f.sigstore.json" \
        --certificate-oidc-issuer='https://token.actions.githubusercontent.com' \
        --certificate-identity-regexp="https://github.com/${GITHUB_REPOSITORY}/.github/workflows/release.yml@refs/.*" \
        "$f"
done

rm -f checksums.txt ./*.sigstore.json

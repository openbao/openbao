#!/usr/bin/env bash

# This script signs release artifacts (Tarballs with binaries, Linux packages,
# SBOMs) via cosign and gpg. Checksums are separately signed as part of
# checksums.sh.

set -euo pipefail

cd dist

# Avoid signing any existing signatures.
artifacts=$(find . -type f -not -name '*.gpgsig' -not -name '*.sigstore.json')

echo "Signing w/ gpg..."

while read -r f; do
    gpg \
        --batch \
        --detach-sign \
        --default-key="$GPG_FINGERPRINT" \
        --output="${f}.gpgsig" \
        "$f" <<< "$GPG_PASSWORD"
done <<< "$artifacts"

echo "Signing w/ cosign..."

while read -r f; do
    cosign sign-blob \
        --yes \
        --bundle="${f}.sigstore.json" \
        "$f"
done <<< "$artifacts"

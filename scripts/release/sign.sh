#!/usr/bin/env bash

# This script signs release artifacts (Tarballs with binaries, Linux packages,
# SBOMs) via cosign and gpg. Checksums are separately signed as part of
# checksums.sh.
#
# We verify each signature after creation to ensure it is valid.

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

    gpg \
        --batch\
        --verify \
        "${f}.gpgsig" \
        "$f"
done <<< "$artifacts"

echo "Signing w/ cosign..."

while read -r f; do
    cosign sign-blob \
        --yes \
        --bundle="${f}.sigstore.json" \
        "$f"

    cosign verify-blob \
        --bundle="${f}.sigstore.json" \
        --certificate-oidc-issuer='https://token.actions.githubusercontent.com' \
        --certificate-identity-regexp='https://github.com/openbao/openbao/.github/workflows/release.yml@refs/heads/(main|release/)' \
        "$f"
done <<< "$artifacts"

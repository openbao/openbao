#!/usr/bin/env bash

# This script signs release artifacts (Tarballs with binaries, Linux packages,
# SBOMs) via cosign and gpg. Checksums are separately signed as part of
# checksums.sh.
#
# We verify each signature after creation to ensure it is valid.

set -euo pipefail

GITHUB_REPOSITORY=${GITHUB_REPOSITORY:-openbao/openbao}
GITHUB_WORKFLOW="https://github.com/${GITHUB_REPOSITORY}/.github/workflows/release.yml"

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
        --batch \
        --verify \
        "${f}.gpgsig" \
        "$f"
done <<< "$artifacts"

echo "Signing w/ cosign..."

case "$GITHUB_REPOSITORY" in
    openbao/openbao)
        # If on the main repository, strictly limit to main and release
        # branches.
        IDENTITY_REGEXP="${GITHUB_WORKFLOW}@refs/heads/(main|release/.+)$"
        ;;
    *)
        # Otherwise, allow releasing from anywhere.
        IDENTITY_REGEXP="${GITHUB_WORKFLOW}@.*"
        ;;
esac

while read -r f; do
    cosign sign-blob \
        --yes \
        --bundle="${f}.sigstore.json" \
        "$f"

    cosign verify-blob \
        --bundle="${f}.sigstore.json" \
        --certificate-oidc-issuer='https://token.actions.githubusercontent.com' \
        --certificate-identity-regexp="$IDENTITY_REGEXP" \
        "$f"
done <<< "$artifacts"

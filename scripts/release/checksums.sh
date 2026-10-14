#!/usr/bin/env bash

# This script creates a checksums.txt for all artifacts in dist/ and signs the
# checksums via cosign and gpg.
#
# We verify each signature after creation to ensure it is valid.

set -euo pipefail

GITHUB_REPOSITORY=${GITHUB_REPOSITORY:-openbao/openbao}
GITHUB_WORKFLOW="https://github.com/${GITHUB_REPOSITORY}/.github/workflows/release.yml"

cd dist

# Checksum all files in dist, except for signatures.
find . -type f -not -name '*.gpgsig' -not -name '*.sigstore.json' -exec basename {} \; \
    | sort \
    | xargs sha256sum \
    > ../checksums.txt && mv ../checksums.txt .

# Sign & verify with cosign:
cosign sign-blob \
    --yes \
    --bundle=checksums.txt.sigstore.json \
    checksums.txt

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

cosign verify-blob \
    --bundle=checksums.txt.sigstore.json \
    --certificate-oidc-issuer='https://token.actions.githubusercontent.com' \
    --certificate-identity-regexp="$IDENTITY_REGEXP" \
    checksums.txt

# Sign & verify with gpg:
gpg \
    --batch \
    --detach-sign \
    --default-key="$GPG_FINGERPRINT" \
    --output=checksums.txt.gpgsig \
    checksums.txt <<< "$GPG_PASSWORD"

gpg \
    --batch \
    --verify \
    checksums.txt.gpgsig \
    checksums.txt

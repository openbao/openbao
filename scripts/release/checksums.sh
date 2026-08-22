#!/usr/bin/env bash

# This script creates a checksums.txt for all artifacts in dist/ and signs the
# checksums via cosign and gpg.
#
# We verify each signature after creation to ensure it is valid.

set -euo pipefail

cd dist

# Checksum all files in dist, except for signatures.
find . -type f -not -name '*.gpgsig' -not -name '*.sigstore.json' -exec basename {} \; \
    | sort \
    | xargs sha256sum \
    > ../checksums.txt && mv ../checksums.txt .

# Sign with cosign:
cosign sign-blob \
    --yes \
    --bundle=checksums.txt.sigstore.json \
    checksums.txt

cosign verify-blob \
    --bundle=checksums.txt.sigstore.json \
    --certificate-oidc-issuer='https://token.actions.githubusercontent.com' \
    --certificate-identity-regexp='https://github.com/openbao/openbao/.github/workflows/release.yml@refs/heads/(main|release/)' \
    checksums.txt

# Sign with gpg:
gpg \
    --batch \
    --detach-sign \
    --default-key="$GPG_FINGERPRINT" \
    --output=checksums.txt.gpgsig \
    checksums.txt <<< "$GPG_PASSWORD"

gpg \
    --batch\
    --verify \
    checksums.txt.gpgsig \
    checksums.txt

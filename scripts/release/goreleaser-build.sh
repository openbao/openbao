#!/usr/bin/env bash

# This script builds a single target using OpenBao's goreleaser configuration.
# This results in exactly one binary, and, depending on the target, several
# archives derived from it including cosign and gpg signatures for those.
#
# The target to build is customizable via the TARGET_OS, TARGET_ARCH and
# TARGET_ARM variables.
#
# When testing locally, it is useful to invoke with additional flags to skip
# some steps:
# $ ./scripts/release/goreleaser-build.sh --snapshot --skip=sign

set -euo pipefail

export TARGET_OS=${TARGET_OS:-$(go env GOOS)}
export TARGET_ARM=${TARGET_ARM:-$(go env GOARM)}
export TARGET_ARCH=${TARGET_ARCH:-$(go env GOARCH)}

VERSION=${VERSION:-$(./scripts/release/nightly-tag.sh)}
export GPG_KEY_FILE=${GPG_KEY_FILE:-/dev/null}

case "$TARGET_OS" in
    linux)
        file=goreleaser.linux.yaml
        ;;
    hsm)
        # Rewrite from 'hsm' to 'linux', but pick the right file.
        export TARGET_OS=linux
        file=goreleaser.hsm.yaml
        ;;
    *)
        file=goreleaser.other.yaml
        ;;
esac

# Inject 'goos' and 'goarch'.
query='
    .builds[0].goos   |= [strenv(TARGET_OS)]
  | .builds[0].goarch |= [strenv(TARGET_ARCH)]
'

# Inject 'goarm' if building for ARM. 
if [[ "$TARGET_OS" == arm ]]; then
    query="$query"' | .builds[0].goarm |= [strenv(TARGET_ARM)]'
fi

# Create the tag locally so goreleaser knows what to target:
git tag "$VERSION"

# Clean up the tag:
trap 'git tag --delete "$VERSION"' EXIT

# Build:
yq eval "$query" "$file" \
    | goreleaser release --clean --verbose --skip=publish --timeout=30m -f - "$@"

# Remove files in 'dist' that we don't want. This leaves only those artifacts
# that we want uploaded to the final release.
rm -rf dist/config.yaml dist/metadata.json dist/artifacts.json dist/builds-*

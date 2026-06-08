#!/usr/bin/env bash

# This script generates the list of container image registries and tags for a
# given repository, image name and version based on tags present in Git.
#
# For example, assuming the latest version globally is "v2.6.0", and we're
# calculating image names for a new "v2.5.5" backport release:
#
# $ VERSION=v2.5.5 ./scripts/release/container-tags.sh
# registries=["ghcr.io", "quay.io", "docker.io"]
# tags<<EOF
# [
#   "ghcr.io/openbao/openbao:2.5",
#   "ghcr.io/openbao/openbao:2.5.5",
#   "quay.io/openbao/openbao:2.5",
#   "quay.io/openbao/openbao:2.5.5",
#   "docker.io/openbao/openbao:2.5",
#   "docker.io/openbao/openbao:2.5.5"
# ]
# EOF
#
# ... we get the "2.5" tag in addition to the absolute "2.5.5", but we won't get
# "2" or "latest" which would be reserved for a version higher than "v2.6.0".

set -euo pipefail

IMAGE_NAME=${IMAGE_NAME:-openbao/openbao}
GITHUB_OUTPUT=${GITHUB_OUTPUT:-/dev/stdout}
GITHUB_REPOSITORY=${GITHUB_REPOSITORY:-openbao/openbao}

# Check that our version is tagged.
if [[ -z "$(git tag --list "$VERSION")" ]]; then
    echo "Tag not found: $VERSION"
    exit 1
fi

version="${VERSION#v}"

case "$GITHUB_REPOSITORY" in
    openbao/openbao|openbao/openbao-nightly)
        registries='["ghcr.io", "quay.io", "docker.io"]'
        ;;
    *)
        registries='["ghcr.io"]'
        ;;
esac

echo "registries=$registries" >> "$GITHUB_OUTPUT"

case "$VERSION" in
    # Pre-release -> Only absolute version.
    v[0-9]*.[0-9]*.[0-9]*-*)
        tags=$(jq -c -n --arg v "$version" '[$v]')
        ;;

    # GA release.
    v[0-9]*.[0-9]*.[0-9])
        IFS=. read -r major minor patch <<< "${VERSION#v}"

        releases=$(git tag --list \
            | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' \
            | sort -r --version-sort)

        latest_major=$(grep -F "v${major}." <<< "$releases" | head -n 1)
        latest_minor=$(grep -F "v${major}.${minor}." <<< "$releases" | head -n 1)

        # Start out with the absolute version.
        tags=$(jq -c -n --arg v "$version" '[$v]')

        # Latest patch in its minor series -> Add "$major.$minor".
        if [[ "$latest_minor" == "$VERSION" ]]; then
            tags=$(jq -c --arg v "${major}.${minor}" '[$v] + .' <<< "$tags")
        fi
        # Latest minor in major series -> Add "$major".
        if [[ "$latest_major" == "$VERSION" ]]; then
            tags=$(jq -c --arg v "${major}" '[$v] + .' <<< "$tags")
        fi
        # Latest overall -> Add "latest".
        if [[ "$(head -n 1 <<< "$releases")" == "$VERSION" ]]; then
            tags=$(jq -c '["latest"] + .' <<< "$tags")
        fi
        ;;
    *)
        echo "Malformed version: $VERSION"
        exit 1
        ;;
esac

echo 'tags<<EOF' >> "$GITHUB_OUTPUT"

# If running in GitHub actions, output JSON in compact mode to be compatible
# with GitHub's parser.
JQ_FLAGS=
if [[ "$GITHUB_OUTPUT" != /dev/stdout ]]; then
    JQ_FLAGS=-c
fi

# This renders the cartesian product of all tags and registries.
jq -n -r $JQ_FLAGS \
    --arg image "${IMAGE_NAME,,}" \
    --argjson tags "$tags" \
    --argjson registries "$registries" \
    '[ $registries[] as $r | $tags[] as $t | "\($r)/\($image):\($t)" ]' \
    >> "$GITHUB_OUTPUT"

echo 'EOF' >> "$GITHUB_OUTPUT"

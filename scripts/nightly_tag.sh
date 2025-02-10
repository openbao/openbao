#!/bin/bash

# This script assumes a strictly linear release version. We assume that,
# while the latest tag may not be on the main branch, we can find it across
# release branches and that incrementing its minor version will be greater
# than any subsequent released patch versions.

candidates=("$(git describe --tags --exclude "api/*" --exclude "sdk/*" --abbrev=0 upstream/main)")
for branch in $(git branch --all | grep 'remotes/upstream/release/[0-9]*\.[0-9]*\.x$' | sed 's#.*remotes/##g'); do
    candidates+=("$(git describe --tags --exclude "api/*" --exclude "sdk/*" --abbrev=0 "$branch")")
done

latest="${candidates[0]}"
latest_timestamp="$(git show --no-patch --format=%ct "${candidates[0]}")"

for candidate in "${candidates[@]}"; do
    timestamp="$(git show --no-patch --format=%ct "$candidate")"
    if [ $(( timestamp > latest_timestamp )) == 1 ]; then
        latest="$candidate"
		latest_timestamp="$timestamp"
    fi
done

echo "Latest tag: $latest @ $latest_timestamp" 1>&2

base_version="$(sed 's/-.*//g' <<< "$latest")"
major_version="$(sed 's/\..*//g' <<< "$latest")"
minor_version="$(sed 's/^v[0-9]*\.\([0-9]*\)\..*/\1/g' <<< "$latest")"
patch_version="$(sed 's/^v[0-9]*\.[0-9]*\.\([0-9]*\)$/\1/g' <<< "$latest")"

echo "base: $base_version" 1>&2
echo "major: $major_version" 1>&2
echo "minor: $minor_version" 1>&2
echo "patch: $patch_version" 1>&2

nightly_timestamp="$(git show --no-patch --format=%ct)"
nightly_minor=$(( minor_version + 1 ))
nightly_version="${major_version}.${nightly_minor}.0-nightly${nightly_timestamp}"

echo "New minor version: $nightly_minor" 1>&2
echo "Nightly version: $nightly_version" 1>&2
echo "$nightly_version"

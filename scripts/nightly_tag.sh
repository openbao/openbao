#!/bin/bash

# This script will print the appropriate nightly tag version for the current
# branch to standard out
#
# - When running on a release branch, only tags on that branch will be
#   considered, defaulting patch to 0, if none is found, bumping patch by one
#   otherwise.
#
# - When running on main (or any other branch) all tags will be, bumping the
#   minor version by one.
#
# If the latest version was a pre-release (v2.0.0-beta) bumping will be skipped

bump="minor"

current_branch=$(git branch --show-current)
if [ "$(dirname "$current_branch")" == "release" ] ; then
    bump="patch"
    major_minor="$(basename "$current_branch" .x)" # turn e.g. 'release/2.5.x' into '2.5'

    latest=$(git describe --tags --match "v${major_minor}.*" --abbrev=0 --always "$current_branch")

    if [ "${latest:0:1}" != "v" ] ; then # if the release branch is new, we will get a commit sha instead (starts with 0-9 or a-f)
        bump="none"
        latest="v${major_minor}.0"
    fi
else
    readarray -t branches < <(git branch --all | grep 'remotes/upstream/release/[0-9]*\.[0-9]*\.x$' | sed 's#.*remotes/##g')
    branches+=("$current_branch")

    latest=$(
        git describe --tags --match "v*" --abbrev=0 "${branches[@]}" \
        | sort --version-sort --reverse \
        | head -n 1
     )
fi

echo "Latest tag: $latest" 1>&2

base_version="$(sed 's/-.*//g' <<< "$latest")"
major_version="$(sed 's/\..*//g' <<< "$base_version")"
minor_version="$(sed 's/^v[0-9]*\.\([0-9]*\)\..*/\1/g' <<< "$base_version")"
patch_version="$(sed 's/^v[0-9]*\.[0-9]*\.\([0-9]*\)$/\1/g' <<< "$base_version")"

if [ "$base_version" != "$latest" ] ; then
    # if the latest version was a beta, don't bump
    bump="none"
fi

echo "base: $base_version" 1>&2
echo "major: $major_version" 1>&2
echo "minor: $minor_version" 1>&2
echo "patch: $patch_version" 1>&2
echo "bumping $bump" 1>&2

nightly_timestamp="$(TZ=UTC0 git show --no-patch --format=%cd --date=format-local:%Y%m%d%H%M)"

case $bump in
    minor)
        minor_version=$(( minor_version + 1 ))
        patch_version=0
        ;;
    patch)
        patch_version=$(( patch_version + 1 ))
        ;;
esac

nightly_version="${major_version}.${minor_version}.${patch_version}-nightly${nightly_timestamp}"

echo "Nightly version: $nightly_version" 1>&2
echo "$nightly_version"

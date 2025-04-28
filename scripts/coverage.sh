#!/bin/sh
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

# Generate test coverage statistics for Go packages.
#
# Works around the fact that `go test -coverprofile` currently does not work
# with multiple packages, see https://code.google.com/p/go/issues/detail?id=6909
#
# Usage: script/coverage [--html|--coveralls|--json] [--pr|<package>]
#
#     --html      Additionally create HTML report and open it in browser
#     --coveralls Push coverage statistics to coveralls.io
#     --json      Output coverage data in JSON format
#     --pr        Only include packages changed in the current PR
#

set -e

workdir=.cover
profile="$workdir/cover.out"
mode=count

generate_cover_data() {
    rm -rf "$workdir"
    mkdir "$workdir"

    for pkg in "$@"; do
        f="$workdir/$(echo $pkg | tr / -).cover"
        # gotestsum --format=short-verbose -- -covermode="$mode" -coverprofile="$f" "$pkg"
        go test -v -covermode="$mode" -coverprofile="$f" "$pkg"
    done

    echo "mode: $mode" >"$profile"
    grep -h -v "^mode:" "$workdir"/*.cover >>"$profile"
}

show_cover_report() {
    go tool cover -${1}="$profile"
}

push_to_coveralls() {
    echo "Pushing coverage statistics to coveralls.io"
    goveralls -coverprofile="$profile"
}

# Get packages to test
if [ "$2" = "--pr" ]; then
    pkgs=$(git diff --name-only origin/main...HEAD | grep '\.go$' | xargs -n1 dirname | sort -u | uniq | xargs -I{} go list ./{} 2>/dev/null)
elif [ -n "$2" ]; then
    pkgs=$(go list ./... | grep -v /vendor/ | grep "$2")
else
    pkgs=$(go list ./... | grep -v /vendor/)
fi

generate_cover_data $pkgs

show_cover_report func

case "$1" in
    "")
        ;;
    --html)
        show_cover_report html
        ;;
    --json)
        cat "$profile" | jq -R -s -c 'split("\n") | map(select(length > 0))'
        ;;
    --coveralls)
        push_to_coveralls
        ;;
    *)
        echo >&2 "error: invalid option: $2"; exit 1
        ;;
esac

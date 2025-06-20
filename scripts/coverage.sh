#!/bin/sh
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

# Generate test coverage statistics for Go packages.
#
# Works around the fact that `go test -coverprofile` currently does not work
# with multiple packages, see https://code.google.com/p/go/issues/detail?id=6909
#
# Usage: scripts/coverage.sh [--html|--coveralls|--json|--pr] <package>
#
#     --html      Additionally create an HTML report and open it in the browser
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
        gotestsum --format=short-verbose -- -covermode="$mode" -coverprofile="$f" "$pkg"
    done

    echo "mode: $mode" >"$profile"
    grep -h -v "^mode:" "$workdir"/*.cover >>"$profile"
}

generate_cover_data_json() {
    rm -rf "$workdir"
    mkdir "$workdir"

    for pkg in "$@"; do
        f="$workdir/$(echo $pkg | tr / -).cover"
        jsonfile="$workdir/$(echo $pkg | tr / -).json"
        gotestsum --format=short-verbose --jsonfile "$jsonfile" -- -covermode="$mode" -coverprofile="$f" "$pkg"
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

while [[ $# -gt 0 ]]; do
    case "$1" in
        --html)
            html=true
            shift
            ;;
        --coveralls)
            coveralls=true
            shift
            ;;
        --json)
            json=true
            shift
            ;;
        --pr)
            pr=true
            shift
            ;;
        *)
            if [ -n "$pr" ]; then
                echo "Error: --pr and package name cannot be used together"
                exit 1
            fi
            searchString="$1"
            shift
            ;;
    esac
done

# Get packages to test
if [ $pr = "true" ]; then
    base_ref=${GITHUB_BASE_REF:-main}
    pkgs=$(git diff --name-only "origin/$base_ref"...HEAD | grep '\.go$' | xargs -n1 dirname | sort -u | uniq | xargs -I{} go list ./{} 2>/dev/null)
elif [ -n "$searchString" ]; then
    pkgs=$(go list ./... | grep -v /vendor/ | grep "$searchString")
else
    pkgs=$(go list ./... | grep -v /vendor/)
fi

if [ $json = "true" ]; then
    echo "Generating JSON coverage data"
    generate_cover_data_json $pkgs
else
    echo "Generating coverage data"
    generate_cover_data $pkgs
fi

show_cover_report func

if [ $html = "true" ]; then
    echo "Generating HTML report"
    show_cover_report html
    echo "HTML report generated at $workdir/cover.html"
fi
if [ $coveralls = "true" ]; then
    push_to_coveralls
fi
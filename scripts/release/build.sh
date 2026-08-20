#!/usr/bin/env bash

# This script invokes the Go compiler for release builds.

set -euo pipefail

export GOOS=${GOOS:-$(go env GOOS)}
export GOARM=${GOARM:-$(go env GOARM)}
export GOARCH=${GOARCH:-$(go env GOARCH)}
export CGO_ENABLED=${CGO_ENABLED:-$(go env CGO_ENABLED)}

case "$GOOS" in
    windows)
        exe=bao.exe
        ;;
    *)
        exe=bao
        ;;
esac

commit=$(git rev-parse HEAD)
commit_date=$(git log -1 --format=%cd --date=format:"%Y-%m-%dT%H:%M:%SZ" HEAD)

# Create a git tag locally so Go picks it up in build metadata.
# See https://github.com/openbao/openbao/issues/3184 for why this matters.
git tag "$VERSION"

# Clean up the tag once done:
trap 'git tag --delete "$VERSION"' EXIT

go build -v -o "bin/${exe}" -tags=ui -buildvcs -ldflags \
    "-X github.com/openbao/openbao/v2/internal/version.fullVersion=${VERSION#v} -X github.com/openbao/openbao/v2/internal/version.GitCommit=${commit} -X github.com/openbao/openbao/v2/internal/version.CommitDate=${commit_date}"

#!/usr/bin/env bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

#
# This script builds the application from source for multiple platforms.
#
# This script should not be used for external release processes; instead,
# invoke `go build` directly; see /.goreleaser-template.yaml for more
# information.
set -e

GO_CMD=${GO_CMD:-go}

# Get the parent directory of where this script is.
SOURCE="${BASH_SOURCE[0]}"
SOURCE_DIR=$( dirname "$SOURCE" )
while [ -h "$SOURCE" ] ; do SOURCE="$(readlink "$SOURCE")"; done
DIR="$( cd -P "$SOURCE_DIR/.." && pwd )"

# Change into that directory
cd "$DIR"

# Set build tags
BUILD_TAGS="${BUILD_TAGS:-"openbao"}"

# Get the git commit
GIT_COMMIT="$(git rev-parse HEAD)"
GIT_DIRTY="$(test -n "`git status --porcelain`" && echo "+CHANGES" || true)"

BUILD_DATE="$(git show --no-show-signature -s --format=%cd --date=format:"%Y-%m-%dT%H:%M:%SZ" HEAD)"

GOPATH=${GOPATH:-$(${GO_CMD} env GOPATH)}
case $(uname) in
    CYGWIN*)
        GOPATH="$(cygpath $GOPATH)"
        ;;
esac

# Delete the old dir
echo "==> Removing old directory..."
rm -f bin/*
rm -rf pkg/*
mkdir -p bin/

# Build!
echo "==> Building bao..."
${GO_CMD} build \
    -gcflags "${GCFLAGS}" \
    -ldflags "${LD_FLAGS} -X github.com/openbao/openbao/version.GitCommit='${GIT_COMMIT}${GIT_DIRTY}' -X github.com/openbao/openbao/version.BuildDate=${BUILD_DATE}" \
    -o "bin/bao" \
    -tags "${BUILD_TAGS}" \
    .

if [ "$1" == "plugin" ]; then
    for etype in logical credential; do
        for plugin in builtin/$etype/*; do
            plugin_name="$(basename "$plugin")"
            if [ ! -e "$plugin/cmd" ]; then
                continue
            fi

            echo "==> Building $plugin..."
            for main in $plugin/cmd/*/main.go; do
                dir="$(dirname "$main")"
                dirname="$(basename "$dir")"
                ${GO_CMD} build \
                    -gcflags "${GCFLAGS}" \
                    -ldflags "${LD_FLAGS} -X github.com/openbao/openbao/version.GitCommit='${GIT_COMMIT}${GIT_DIRTY}' -X github.com/openbao/openbao/version.BuildDate=${BUILD_DATE}" \
                    -o "bin/$etype-$plugin_name-$dirname" \
                    -tags "${BUILD_TAGS}" \
                    github.com/openbao/openbao/$dir
            done
        done
    done
fi

# Move all the compiled things to the $GOPATH/bin
OLDIFS=$IFS
IFS=: FIRST=($GOPATH) BIN_PATH=${GOBIN:-${FIRST}/bin}
IFS=$OLDIFS

# Ensure the go bin folder exists
mkdir -p ${BIN_PATH}
rm -f ${BIN_PATH}/bao
cp bin/bao ${BIN_PATH}

# Done!
echo
echo "==> Results:"
ls -hl bin/

#!/usr/bin/env bash

# This script creates an archive (.tar.gz or .zip depending on Windows or not)
# from a release binary, bundling it with LICENSE, README.md and CHANGELOG.md.

set -euo pipefail

export GOOS=${GOOS:-$(go env GOOS)}
export GOARM=${GOARM:-$(go env GOARM)}
export GOARCH=${GOARCH:-$(go env GOARCH)}

mkdir -p dist && cd dist

archive="openbao_${VERSION#v}_${GOOS}_${GOARCH}"

# Add the ARM suffix if this is an ARM build.
if [[ -n "${GOARM:-}" ]]; then
    archive="${archive}v${GOARM}"
fi

case "$GOOS" in
    windows)
        zip -j -X \
            "${archive}.zip" \
            ../bin/bao.exe ../LICENSE ../README.md ../CHANGELOG.md
        ;;
    *)
        tar czf \
            "${archive}.tar.gz" \
            -C ../bin bao -C .. LICENSE README.md CHANGELOG.md
        ;;
esac

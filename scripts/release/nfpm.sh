#!/usr/bin/env bash

set -euo pipefail

export GOOS=${GOOS:-$(go env GOOS)}
export GOARM=${GOARM:-$(go env GOARM)}
export GOARCH=${GOARCH:-$(go env GOARCH)}

package="openbao_${VERSION#v}_${GOOS}_${GOARCH}"

# Add the ARM suffix if this is an ARM build.
if [[ -n "${GOARM:-}" ]]; then
    package="${package}v${GOARM}"
fi

case "${NFPM_PACKAGER}" in
    deb)
        ext="deb"
        ;;
    rpm)
        ext="rpm"
        ;;
    archlinux)
        ext="pkg.tar.zst"
        ;;
    *)
        echo "don't know file extension for packager: ${NFPM_PACKAGER}"
        exit 1
esac

nfpm package \
    --config ./.release/nfpm.yaml \
    --packager "$NFPM_PACKAGER" \
    --target "dist/${package}.${ext}"

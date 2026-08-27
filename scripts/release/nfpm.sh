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

# nFPM mostly takes GOOS/GOARCH as-is but has no GOARM equivalent, which must
# effectively be appended to GOARCH. Note that nFPM will *happily* take a plain
# GOARCH=arm and produce complete nonsense that no downstream tool can work
# with, so removing this line won't break here but later.
# Also see: https://nfpm.goreleaser.com/docs/arch-mapping
export GOARCH="${GOARCH}${GOARM}"

nfpm package \
    --config ./.release/nfpm.yaml \
    --packager "$NFPM_PACKAGER" \
    --target "dist/${package}.${ext}"

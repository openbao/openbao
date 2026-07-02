#!/usr/bin/env bash

# This script updates an RPM package repository under build/ based on .rpm
# packages available under dist/. The repository does not need to exist yet.

set -euo pipefail

for rpm in dist/*.rpm; do
    arch=$(rpm -q "$rpm" --qf "%{arch}")
    mkdir -p "build/rpm/$arch"
    mv "$rpm" "build/rpm/$arch"
    createrepo_c \
        --update \
        --recycle-pkglist \
        --skip-stat \
        --includepkg \
        "$(basename "$rpm")" \
        "build/rpm/$arch"
done

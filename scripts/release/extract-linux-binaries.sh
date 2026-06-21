#!/usr/bin/env bash

# This script extracts Linux binaries from release tarballs in dist/ into bin/,
# creating a layout compatible for multi-arch Docker image builds.
#
# Useful in combination with scripts/release/download-artifacts.sh.

set -euo pipefail

for archive in dist/*.tar.gz; do
    arch=$(
      echo "$archive" \
        | sed -E 's/.*_linux_([^.]+)\.tar\.gz/\1/' \
        | sed -E 's/arm(v6|v7)/arm/'
    )
    mkdir -p "bin/$arch" && tar xf "$archive" -C "bin/$arch" bao
done

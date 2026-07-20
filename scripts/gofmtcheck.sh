#!/usr/bin/env bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

echo "==> Checking that code complies with gofumpt..."

files=$(echo $1 | xargs)
if [[ -n "$files" ]]; then
    echo "Checking changed files..."
    gofmt_files="$(echo $1 | grep -F -v .pb.go | xargs go tool -modfile=tools/go.mod gofumpt -l)"
else
    echo "Checking all files..."
    gofmt_files="$(go tool -modfile=tools/go.mod gofumpt -l .)"
fi

if [[ -n "${gofmt_files}" ]]; then
    echo 'gofumpt needs running on the following files:'
    echo "${gofmt_files}"
    echo "You can use the command: \`make fmt\` to reformat code."
    exit 1
fi

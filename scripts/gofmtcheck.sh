#!/usr/bin/env bash

echo "==> Checking that code complies with gofumpt requirements..."

gofmt_files=$(gofumpt -l `find . -name '*.go'`)
if [[ -n ${gofmt_files} ]]; then
    echo 'gofumpt needs running on the following files:'
    echo "${gofmt_files}"
    echo "You can use the command: \`make fmt\` to reformat code."
    exit 1
fi
#!/bin/sh

set -e

TOOL=vault-plugin-auth-jwt

## Make a temp dir
tempdir=$(mktemp -d update-${TOOL}-deps.XXXXXX)

## Set paths
export GOPATH="$(pwd)/${tempdir}"
export PATH="${GOPATH}/bin:${PATH}"
cd $tempdir

## Get tool
mkdir -p src/github.com/hashicorp
cd src/github.com/hashicorp
echo "Fetching ${TOOL}..."
git clone https://github.com/hashicorp/${TOOL}.git
cd ${TOOL}

## Get golang dep tool
go get -u github.com/golang/dep/cmd/dep

## Remove existing manifest
rm -rf Gopkg* vendor

## Init
dep init

## Fetch deps
echo "Fetching deps, will take some time..."
dep ensure
echo "Pruning unused deps..."
dep prune

echo "Done; to commit run \n\ncd ${GOPATH}/src/github.com/hashicorp/${TOOL}\n"

#!/usr/bin/env bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

set -e

PLUGIN_NAME="openldap"
PLUGIN_CATALOG_NAME="openldap"

#
# Helper script for local development. Automatically builds and registers the
# plugin. Requires `vault` is installed and available on $PATH.
#

# Get the right dir
DIR="$(cd "$(dirname "$(readlink "$0")")" && pwd)"

echo "==> Starting dev"

echo "--> Scratch dir"
echo "    Creating"
SCRATCH="$DIR/tmp"
mkdir -p "$SCRATCH/plugins"

echo "--> Vault server"

echo "    Envvars"
export VAULT_DEV_ROOT_TOKEN_ID="root"
export VAULT_ADDR="http://127.0.0.1:8200"

echo "    Starting"
vault server \
  -dev \
  -dev-root-token-id=root \
  -dev-plugin-dir="$SCRATCH/plugins" \
  -log-level="debug" \
  &
VAULT_PID=$!
sleep 2

function cleanup {
  echo ""
  echo "==> Cleaning up"
  kill -INT "$VAULT_PID"
  wait $VAULT_PID
  rm -rf "$SCRATCH"
}
trap cleanup EXIT

echo "    Authing"
vault login root &>/dev/null

echo "--> Building"
go build -o "$SCRATCH/plugins/$PLUGIN_NAME" "./cmd/$PLUGIN_NAME" 
SHASUM=$(shasum -a 256 "$SCRATCH/plugins/$PLUGIN_NAME" | cut -d " " -f1)

echo "    Registering plugin"
vault write sys/plugins/catalog/$PLUGIN_CATALOG_NAME \
  sha_256="$SHASUM" \
  command="$PLUGIN_NAME"

echo "    Mounting plugin"
vault secrets enable openldap

if [ -e scripts/custom.sh ]
then
  . scripts/custom.sh
fi

echo "==> Ready!"
wait $!

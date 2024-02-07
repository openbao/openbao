#!/bin/bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0


set -e

# Generate an OpenAPI document for all backends.
#
# Assumptions:
#
#   1. OpenBao has been checked out at an appropriate version and built
#   2. bao executable is in your path
#   3. OpenBao isn't already running
#   4. jq is installed

cd "$(dirname "${BASH_SOURCE[0]}")"

echo "Starting OpenBao..."
if pgrep -x "bao" > /dev/null
then
    echo "OpenBao is already running. Aborting."
    exit 1
fi

bao server -dev -dev-root-token-id=root &
BAO_PID=$!

# Allow time for OpenBao to start its HTTP listener
sleep 1

defer_stop_bao() {
    echo "Stopping OpenBao..."
    kill $BAO_PID
    # Allow time for OpenBao to print final logging and exit,
    # before this script ends, and the shell prints its next prompt
    sleep 1
}

trap defer_stop_bao INT TERM EXIT

export VAULT_ADDR=http://127.0.0.1:8200

echo "Unmounting the default kv-v2 secrets engine ..."

# Unmount the default kv-v2 engine so that we can remount it at 'kv_v2/' later.
# The mount path will be reflected in the resultant OpenAPI document.
bao secrets disable "secret/"

echo "Mounting all builtin plugins ..."

# Enable auth plugins
bao auth enable "approle"
bao auth enable "cert"
bao auth enable "jwt"
bao auth enable "kerberos"
bao auth enable "kubernetes"
bao auth enable "ldap"
bao auth enable "radius"
bao auth enable "userpass"

# Enable secrets plugins
bao secrets enable "database"
bao secrets enable "kubernetes"
bao secrets enable -path="kv-v1/" -version=1 "kv"
bao secrets enable -path="kv-v2/" -version=2 "kv"
bao secrets enable "ldap"
bao secrets enable "pki"
bao secrets enable "rabbitmq"
bao secrets enable "ssh"
bao secrets enable "totp"
bao secrets enable "transit"

# Output OpenAPI, optionally formatted
if [ "$1" == "-p" ]; then
    curl --header 'X-Vault-Token: root' \
         --data '{"generic_mount_paths": true}' \
            'http://127.0.0.1:8200/v1/sys/internal/specs/openapi' | jq > openapi.json
else
    curl --header 'X-Vault-Token: root' \
         --data '{"generic_mount_paths": true}' \
            'http://127.0.0.1:8200/v1/sys/internal/specs/openapi' > openapi.json
fi

echo
echo "openapi.json generated"
echo

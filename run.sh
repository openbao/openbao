#!/bin/bash

set -euxo pipefail

( killall bao && sleep 1 ) || true

devbao node start --force --initialize --unseal --profiles secret,userpass,pki,transit --audit --seals static:// --ui

. <(devbao node env prod)

bao write sys/external-keys/configs/transit plugin=transit token=$VAULT_TOKEN address=$VAULT_ADDR mount_path=transit
bao write sys/external-keys/configs/transit/keys/key name=auto-unseal
bao write -f sys/external-keys/configs/transit/keys/key/grants/transit

bao write transit/keys/external external_key_name=transit:key type=external_key
bao write transit/encrypt/external plaintext=asdf

# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

PLUGIN_DIR=$1
PLUGIN_NAME=$2
TEST_REDIS_HOST=$3
TEST_REDIS_PORT=$4
TEST_REDIS_USERNAME=$5
TEST_REDIS_PASSWORD=$6

vault plugin deregister "$PLUGIN_NAME"
vault secrets disable database
killall "$PLUGIN_NAME"

# Give a bit of time for the binary file to be released so we can copy over it
sleep 3

# Copy the binary so text file is not busy when rebuilding & the plugin is registered
cp ./bin/"$PLUGIN_NAME" "$PLUGIN_DIR"/"$PLUGIN_NAME"

# Sets up the binary with local changes
vault secrets enable database
vault plugin register \
      -sha256="$(shasum -a 256 "$PLUGIN_DIR"/"$PLUGIN_NAME" | awk '{print $1}')" \
      database "$PLUGIN_NAME"

# Configure & test the new registered plugin
vault write database/config/local-redis \
      plugin_name="$PLUGIN_NAME" \
    	allowed_roles="*" \
    	host="$TEST_REDIS_HOST" \
    	port="$TEST_REDIS_PORT" \
    	username="$TEST_REDIS_USERNAME" \
    	password="$TEST_REDIS_PASSWORD" \
    	insecure_tls=true

vault write database/roles/my-dynamic-role \
    db_name="local-redis" \
    creation_statements='["+@read"]' \
    default_ttl="5m" \
    max_ttl="1h"

vault read database/creds/my-dynamic-role
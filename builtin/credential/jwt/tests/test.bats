#!/usr/bin/env bats

# See the vault-plugin-auth-jwt README for prereqs and setup.

# Vault logs will be written to VAULT_OUTFILE.
# BATs test logs will be written to SETUP_TEARDOWN_OUTFILE.

export VAULT_ADDR='http://127.0.0.1:8200'
SETUP_TEARDOWN_OUTFILE=/tmp/bats-test.log
VAULT_OUTFILE=/tmp/vault.log
VAULT_TOKEN='root'
VAULT_STARTUP_TIMEOUT=15

# error if these are not set
[ ${CLIENT_ID:?} ]
[ ${CLIENT_SECRET:?} ]
[ ${ISSUER:?} ]
[ ${VAULT_LICENSE:?} ]

# assert_status evaluates if `status` is equal to $1. If they are not equal a
# log is written to the output file. This makes use of the BATs `status` and
# `output` globals.
#
# Parameters:
#   expect
# Globals:
#   status
#   output
assert_status() {
  local expect
  expect="$1"

  [ "${status}" -eq "${expect}" ] || \
    log_err "bad status: expect: ${expect}, got: ${status} \noutput:\n${output}"
}

log() {
  echo "INFO: $(date): [$BATS_TEST_NAME]: $@" >> $SETUP_TEARDOWN_OUTFILE
}

log_err() {
  echo -e "ERROR: $(date): [$BATS_TEST_NAME]: $@" >> $SETUP_TEARDOWN_OUTFILE
  exit 1
}

# setup_file runs once before all tests
setup_file(){
    # clear log file
    echo "" > $SETUP_TEARDOWN_OUTFILE

    VAULT_TOKEN='root'

    log "BEGIN SETUP"

    if [[ -n ${VAULT_IMAGE} ]]; then
      log "docker using VAULT_IMAGE: $VAULT_IMAGE"
      docker pull ${VAULT_IMAGE?}

      docker run \
        --name=vault \
        --hostname=vault \
        -p 8200:8200 \
        -e VAULT_DEV_ROOT_TOKEN_ID="root" \
        -e VAULT_ADDR="http://localhost:8200" \
        -e VAULT_DEV_LISTEN_ADDRESS="0.0.0.0:8200" \
        -e VAULT_LICENSE="${VAULT_LICENSE?}" \
        --privileged \
        --detach ${VAULT_IMAGE?}
    else
      log "using local vault binary"
      ./vault server -dev -dev-root-token-id=root \
        -log-level=trace > $VAULT_OUTFILE 2>&1 &
    fi

    log "waiting for vault..."
    i=0
    while ! vault status >/dev/null 2>&1; do
      sleep 1
      ((i=i+1))
      [ $i -gt $VAULT_STARTUP_TIMEOUT ] && log_err "timed out waiting for vault to start"
    done

    vault login ${VAULT_TOKEN?}

    run vault status
    assert_status 0
    log "vault started successfully"

    vault namespace create ns1

    log "END SETUP"
}

# teardown_file runs once after all tests complete
teardown_file(){
    log "BEGIN TEARDOWN"

    if [[ -n ${VAULT_IMAGE} ]]; then
      log "removing vault docker container"
      docker rm vault --force
    else
      log "killing vault process"
      pkill vault
    fi

    log "END TEARDOWN"
}

@test "Enable oidc auth" {
    run vault auth enable --namespace=ns1 oidc
    assert_status 0
}

@test "Setup kv and policies" {
    run vault secrets enable --namespace=ns1 -version=2 kv
    assert_status 0

    run vault kv put --namespace=ns1 kv/my-secret/secret-1 value=1234
    assert_status 0

    run vault kv put --namespace=ns1 kv/your-secret/secret-2 value=5678
    assert_status 0

    run vault policy write --namespace=ns1 test-policy -<<EOF
path "kv/data/my-secret/*" {
  capabilities = [ "read" ]
}

EOF
    assert_status 0

}

@test "POST /auth/oidc/config - write config" {
    run vault write --namespace=ns1 auth/oidc/config \
      oidc_discovery_url="$ISSUER" \
      oidc_client_id="$CLIENT_ID" \
      oidc_client_secret="$CLIENT_SECRET" \
      default_role="test-role" \
      bound_issuer="localhost"
    assert_status 0
}

@test "POST /auth/oidc/role/:name - create a role" {
    run vault write --namespace=ns1 auth/oidc/role/test-role \
      user_claim="sub" \
      allowed_redirect_uris="http://localhost:8250/oidc/callback,http://localhost:8200/ui/vault/auth/oidc/oidc/callback" \
      bound_audiences="$CLIENT_ID" \
      oidc_scopes="openid" \
      ttl=1h \
      policies="test-policy" \
      verbose_oidc_logging=true
    assert_status 0

    run vault write --namespace=ns1 auth/oidc/role/test-role-2 \
      user_claim="sub" \
      allowed_redirect_uris="http://localhost:8250/oidc/callback,http://localhost:8200/ui/vault/auth/oidc/oidc/callback" \
      bound_audiences="$CLIENT_ID" \
      oidc_scopes="openid" \
      ttl=1h \
      policies="test-policy" \
      verbose_oidc_logging=true
    assert_status 0
}

@test "LIST /auth/oidc/role - list roles" {
    run vault list --namespace=ns1 auth/oidc/role
    assert_status 0
}

@test "GET /auth/oidc/role/:name - read a role" {
    run vault read --namespace=ns1 auth/oidc/role/test-role
    assert_status 0
}

@test "DELETE /auth/oidc/role/:name - delete a role" {
    run vault delete --namespace=ns1 auth/oidc/role/test-role-2
    assert_status 0
}

# this test will open your default browser and ask you to login with your
# OIDC Provider
@test "Login with oidc auth" {
    unset VAULT_TOKEN
    run vault login --namespace=ns1 -method=oidc
    assert_status 0
}

@test "Test policy prevents kv read" {
    unset VAULT_TOKEN
    run vault kv get --namespace=ns1 kv/your-secret/secret-2
    assert_status 2
}

@test "Test policy allows kv read" {
    unset VAULT_TOKEN
    run vault kv get --namespace=ns1 kv/my-secret/secret-1
    assert_status 0
}

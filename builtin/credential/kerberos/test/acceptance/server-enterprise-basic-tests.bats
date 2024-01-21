#!/usr/bin/env bats

# First run 'make bin' to generate a linux binary in the pkg directory,
# then run bats from the root directory of the project - not from here!

load _helpers

export VAULT_ADDR="http://127.0.0.1:8200"
export VAULT_NAMESPACE=${VAULT_NAMESPACE:-"admin/"}

# todo: Whenever we add Vault OSS acceptance test,
# we will have to make this conditional based on that
if [[ -z "${VAULT_LICENSE}" ]]; then
    echo "VAULT_LICENSE env var not set" >&2
    exit 1
fi

# setup sets up the infrastructure required for running these tests
setup_file() {
  start_infrastructure

  setup_users
  add_vault_spn
  prepare_outer_environment
}

teardown_file() {
  stop_infrastructure
}

create_namespace() {
  new_namespace=${VAULT_NAMESPACE}
  VAULT_NAMESPACE=""
  vault namespace create "$new_namespace"
}

register_plugin() {
  plugin_binary_path="$(plugin_dir)/vault-plugin-auth-kerberos"
  VAULT_PLUGIN_SHA=$(openssl dgst -sha256 "$plugin_binary_path" | cut -d ' ' -f2)
  VAULT_NAMESPACE=""

  vault write sys/plugins/catalog/auth/kerberos sha_256="${VAULT_PLUGIN_SHA}" command="vault-plugin-auth-kerberos"
}

enable_and_config_auth_kerberos() {
  vault auth enable \
    -path=kerberos \
    -passthrough-request-headers=Authorization \
    -allowed-response-headers=www-authenticate \
    vault-plugin-auth-kerberos

  vault write auth/kerberos/config \
    keytab=@vault_svc.keytab.base64 \
    service_account="vault_svc"

  vault write auth/kerberos/config/ldap \
    binddn="${DOMAIN_VAULT_ACCOUNT}"@"${REALM_NAME}" \
    bindpass="${DOMAIN_VAULT_PASS}" \
    groupattr=sAMAccountName \
    groupdn="${DOMAIN_DN}" \
    groupfilter="(&(objectClass=group)(member:1.2.840.113556.1.4.1941:={{.UserDN}}))" \
    insecure_tls=true \
    starttls=true \
    userdn="CN=Users,${DOMAIN_DN}" \
    userattr=sAMAccountName \
    upndomain="${REALM_NAME}" \
    url=ldaps://"${SAMBA_CONTAINER:0:12}"."${DNS_NAME}"
}

login_kerberos() {
  docker cp "${BATS_TEST_DIRNAME}"/auth-check.py "$DOMAIN_JOINED_CONTAINER":/home
  docker exec -it "$DOMAIN_JOINED_CONTAINER" python /home/auth-check.py "$VAULT_CONTAINER" "${VAULT_NAMESPACE}"
}

assert_success() {
  if [ ! "${status?}" -eq 0 ]; then
    echo "${output}"
    exit $status
  fi
}

@test "auth/kerberos: create namespace" {
  run create_namespace
  assert_success
}

@test "auth/kerberos: register plugin" {
  run register_plugin
  assert_success
}

@test "auth/kerberos: enable and configure auth method" {
  run enable_and_config_auth_kerberos
  assert_success
}

@test "auth/kerberos: setup and authentication within a Vault namespace" {
  run login_kerberos
  assert_success

  [[ "${output?}" =~ ^Vault[[:space:]]token\:[[:space:]].+$ ]]
}

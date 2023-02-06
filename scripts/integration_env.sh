#!/bin/bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0


set -eo pipefail

REPO_ROOT="$(readlink -f $(git rev-parse --show-toplevel || echo .))"
VAULT_IMAGE_TAG="$(curl -fsSL 'https://api.github.com/repos/hashicorp/vault/tags?page=1' | jq -r '.[0].name' | sed -e 's/^v//')"
VAULT_PORT=8200
SAMBA_VER=4.8.12

export VAULT_TOKEN=${VAULT_TOKEN:-myroot}
DOMAIN_ADMIN_PASS=Pa55word!
DOMAIN_VAULT_ACCOUNT=vault_svc
DOMAIN_VAULT_PASS=vaultPa55word!
DOMAIN_USER_ACCOUNT=grace
DOMAIN_USER_PASS=gracePa55word!

SAMBA_CONF_FILE=/srv/etc/smb.conf
DOMAIN_NAME=matrix
DNS_NAME=matrix.lan
REALM_NAME=MATRIX.LAN
DOMAIN_DN=DC=MATRIX,DC=LAN
TESTS_DIR="$(mktemp -d -t tests-XXXXXXXX)"

function start_infrastructure() {
  create_network
  start_domain
  start_vault
}

function stop_container() {
    local name="$1"
    if [ -n "${name}" ]; then
        docker rm -f "${name}"
    fi
}

function stop_infrastructure() {
  stop_domain_joined_container
  stop_vault
  stop_domain
  delete_network
}

function tear_down() {
  rm -rf "${TESTS_DIR}"
  stop_infrastructure
}

function create_network() {
  docker network create ${DNS_NAME}
}

function delete_network() {
  docker network rm ${DNS_NAME}
}

function start_vault() {
  VAULT_CONTAINER=$(docker run --net=${DNS_NAME} -d -ti --cap-add=IPC_LOCK \
    -v "${REPO_ROOT}:/tmp/repo-root:Z" \
    -e "VAULT_DEV_ROOT_TOKEN_ID=${VAULT_TOKEN}" \
    -e "VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:${VAULT_PORT}" \
    -p ${VAULT_PORT}:${VAULT_PORT} \
    hashicorp/vault:${VAULT_IMAGE_TAG} server -dev -dev-plugin-dir=/tmp/repo-root/pkg/linux_amd64)
  export VAULT_ADDR=http://127.0.0.1:${VAULT_PORT}
}

function stop_vault() {
  stop_container ${VAULT_CONTAINER}
}

function start_domain() {
  SAMBA_CONTAINER=$(docker run --net=${DNS_NAME} -d -ti --privileged \
    -p 135:135 -p 137:137 -p 138:138 -p 139:139 -p 389:389 -p 445:445 -p 464:464 -p 636:636 -p 3268:3268 -p 3269:3269 \
    -e "SAMBA_DC_ADMIN_PASSWD=${DOMAIN_ADMIN_PASS}" \
    -e "KERBEROS_PASSWORD=${DOMAIN_ADMIN_PASS}" \
    -e SAMBA_DC_DOMAIN=${DOMAIN_NAME} \
    -e SAMBA_DC_REALM=${REALM_NAME} "bodsch/docker-samba4:${SAMBA_VER}")
  # shouldn't need to publish all these ports as they are only used within the docker network, but figured it may be useful for debugging
}

function stop_domain() {
  stop_container ${SAMBA_CONTAINER}
}

function setup_users() {
  add_user $DOMAIN_VAULT_ACCOUNT $DOMAIN_VAULT_PASS
  create_keytab $DOMAIN_VAULT_ACCOUNT $DOMAIN_VAULT_PASS

  add_user $DOMAIN_USER_ACCOUNT $DOMAIN_USER_PASS
  create_keytab $DOMAIN_USER_ACCOUNT $DOMAIN_USER_PASS
}

function add_user() {

  username="${1}"
  password="${2}"

  if [[ $(check_user ${username}) -eq 0 ]]
  then
    echo "add user '${username}'"

    docker exec $SAMBA_CONTAINER \
      /usr/bin/samba-tool user create \
      ${username} \
      ${password}\
      --configfile=${SAMBA_CONF_FILE}
  fi
}

function check_user() {

  username="${1}"

  docker exec $SAMBA_CONTAINER \
    /usr/bin/samba-tool user list \
    --configfile=${SAMBA_CONF_FILE} \
    | grep -c ${username}
}

function create_keytab() {
  username="${1}"
  password="${2}"

  user_kvno=$(docker exec $SAMBA_CONTAINER \
    bash -c "ldapsearch -H ldaps://localhost -D \"Administrator@${REALM_NAME}\"  -w \"${DOMAIN_ADMIN_PASS}\" -b \"CN=Users,${DOMAIN_DN}\" -LLL \"(&(objectClass=user)(sAMAccountName=${username}))\" msDS-KeyVersionNumber | sed -n 's/^[ \t]*msDS-KeyVersionNumber:[ \t]*\(.*\)/\1/p'")

  docker exec $SAMBA_CONTAINER \
    bash -c "printf \"%b\" \"addent -password -p \"${username}@${REALM_NAME}\" -k ${user_kvno} -e rc4-hmac\n${password}\nwrite_kt ${username}.keytab\" | ktutil"

  docker exec $SAMBA_CONTAINER \
    bash -c "printf \"%b\" \"read_kt ${username}.keytab\nlist\" | ktutil"

  docker exec $SAMBA_CONTAINER \
    base64 ${username}.keytab > ${username}.keytab.base64
}

function add_vault_spn() {
  docker exec $SAMBA_CONTAINER \
    samba-tool spn add HTTP/${VAULT_CONTAINER:0:12} ${DOMAIN_VAULT_ACCOUNT} --configfile=${SAMBA_CONF_FILE}
  docker exec $SAMBA_CONTAINER \
    samba-tool spn add HTTP/${VAULT_CONTAINER:0:12}:${VAULT_PORT} ${DOMAIN_VAULT_ACCOUNT} --configfile=${SAMBA_CONF_FILE}
  docker exec $SAMBA_CONTAINER \
    samba-tool spn add HTTP/${VAULT_CONTAINER:0:12}.${DNS_NAME} ${DOMAIN_VAULT_ACCOUNT} --configfile=${SAMBA_CONF_FILE}
  docker exec $SAMBA_CONTAINER \
    samba-tool spn add HTTP/${VAULT_CONTAINER:0:12}.${DNS_NAME}:${VAULT_PORT} ${DOMAIN_VAULT_ACCOUNT} --configfile=${SAMBA_CONF_FILE}
}

function exec_vault() {
    docker exec -e VAULT_ADDR="http://127.0.0.1:8200" -e VAULT_TOKEN="${VAULT_TOKEN}" "${VAULT_CONTAINER}" vault "$@"
}

function enable_plugin() {
  VAULT_PLUGIN_SHA=$(openssl dgst -sha256 pkg/linux_amd64/vault-plugin-auth-kerberos|cut -d ' ' -f2)
  exec_vault write sys/plugins/catalog/auth/kerberos sha_256=${VAULT_PLUGIN_SHA} command="vault-plugin-auth-kerberos"
  exec_vault auth enable -passthrough-request-headers=Authorization -allowed-response-headers=www-authenticate kerberos
  exec_vault write auth/kerberos/config keytab=@/tmp/repo-root/vault_svc.keytab.base64 service_account="vault_svc"
  exec_vault write auth/kerberos/config/ldap \
    binddn=${DOMAIN_VAULT_ACCOUNT}@${REALM_NAME} bindpass=${DOMAIN_VAULT_PASS} \
    groupattr=sAMAccountName \
    groupdn="${DOMAIN_DN}" \
    groupfilter="(&(objectClass=group)(member:1.2.840.113556.1.4.1941:={{.UserDN}}))" \
    insecure_tls=true starttls=true \
    userdn="CN=Users,${DOMAIN_DN}" userattr=sAMAccountName \
    upndomain=${REALM_NAME} \
    url=ldaps://${SAMBA_CONTAINER:0:12}.${DNS_NAME}
}

function write_python_test() {
  sleep 10 # this is a naive way to wait until the containers are up
  echo "
import sys

import kerberos
import requests

host = \"${VAULT_CONTAINER:0:12}.${DNS_NAME}:${VAULT_PORT}\"
service = \"HTTP@{}\".format(host)
rc, vc = kerberos.authGSSClientInit(service=service, mech_oid=kerberos.GSS_MECH_OID_SPNEGO)
kerberos.authGSSClientStep(vc, \"\")
kerberos_token = kerberos.authGSSClientResponse(vc)

r = requests.post(\"http://{}/v1/auth/kerberos/login\".format(host),
                  headers={'Authorization': 'Negotiate ' + kerberos_token})
if r.status_code != 200:
    sys.exit('Python test: Expected Vault login success, response={}'.format(r))

token = r.json().get('auth', dict()).get('client_token')
if token is None:
    sys.exit('Python test: Expected client token, got {}'.format(token))

print('Python test: Vault login succeeded, got token {}'.format(token))
" > manual_test.py
}

function write_kerb_config() {
  echo "
[libdefaults]
  default_realm = ${REALM_NAME}
  dns_lookup_realm = false
  dns_lookup_kdc = true
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = true
    rdns = false
  preferred_preauth_types = 23
[realms]
  ${REALM_NAME} = {
    kdc = ${SAMBA_CONTAINER:0:12}.${DNS_NAME}
    admin_server = ${SAMBA_CONTAINER:0:12}.${DNS_NAME}
    master_kdc = ${SAMBA_CONTAINER:0:12}.${DNS_NAME}
    default_domain = ${SAMBA_CONTAINER:0:12}.${DNS_NAME}
  }
" > krb5.conf
}

function prepare_files() {
  chmod 0755 "${TESTS_DIR}"
  mkdir -p ${TESTS_DIR}/integration
  pushd ${TESTS_DIR}/integration
  write_kerb_config
  write_python_test
  popd
  eval base64 -d grace.keytab.base64 > $TESTS_DIR/integration/grace.keytab
}

function start_domain_joined_container() {
  DOMAIN_JOINED_CONTAINER=$(docker run --net=${DNS_NAME} -d \
    -v "${TESTS_DIR}/integration:/tests:Z" \
    -e KRB5_CONFIG=/tests/krb5.conf \
    -e KRB5_CLIENT_KTNAME=/tests/grace.keytab \
    -t python:3.7 cat)
}

function stop_domain_joined_container() {
  stop_container ${DOMAIN_JOINED_CONTAINER}
}

function run_test_script() {
  # execute a login from go and record result
  docker cp bin/login-kerb $DOMAIN_JOINED_CONTAINER:/usr/local/bin/login-kerb
  VAULT_CONTAINER_PREFIX=${VAULT_CONTAINER:0:12}
  docker exec $DOMAIN_JOINED_CONTAINER \
    login-kerb \
      -username=$DOMAIN_USER_ACCOUNT \
      -service="HTTP/$VAULT_CONTAINER_PREFIX.$DNS_NAME:8200" \
      -realm=$REALM_NAME \
      -keytab_path="/tests/grace.keytab" \
      -krb5conf_path="/tests/krb5.conf" \
      -vault_addr="http://$VAULT_CONTAINER_PREFIX.$DNS_NAME:8200"
  normal_login_result=$?
  docker exec $DOMAIN_JOINED_CONTAINER \
    login-kerb \
      -username=$DOMAIN_USER_ACCOUNT \
      -service="HTTP/$VAULT_CONTAINER_PREFIX.$DNS_NAME:8200" \
      -realm=$REALM_NAME \
      -keytab_path="/tests/grace.keytab" \
      -krb5conf_path="/tests/krb5.conf" \
      -vault_addr="http://$VAULT_CONTAINER_PREFIX.$DNS_NAME:8200" \
      -disable_fast_negotiation
  active_dir_login_result=$?

  # execute a login from python and record result
  docker exec $DOMAIN_JOINED_CONTAINER \
    pip install --quiet requests-kerberos kerberos
  docker exec $DOMAIN_JOINED_CONTAINER \
    python /tests/manual_test.py
  python_login_result=$?
}

function run_tests() {
  prepare_files
  start_domain_joined_container
  run_test_script
}

function main() {
  trap tear_down EXIT SIGINT
  start_infrastructure

  sleep 15  # could loop until `ldapsearch` returns properly....
  setup_users
  add_vault_spn
  enable_plugin
  run_tests
  if [ ! $python_login_result = 0 ]; then
    echo "python login failed"
    return $python_login_result
  fi
  if [ ! $normal_login_result = 0 ]; then
    echo "normal go login failed"
    return $normal_login_result
  fi
  if [ ! $active_dir_login_result = 0 ]; then
    echo "active directory go login failed"
    return $active_dir_login_result
  fi
  echo "Tests completed successfully"
  return 0
}
main

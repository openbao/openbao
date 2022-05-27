#!/bin/bash

if [[ "$OSTYPE" == "darwin"* ]]; then
  sleepcmd="while true; do sleep 86400; done"
else
  sleepcmd="sleep infinity"
fi

VAULT_IMAGE_TAG=$(curl https://api.github.com/repos/hashicorp/vault/tags?page=1 | python -c "import sys, json; print(json.load(sys.stdin)[0]['name'][1:])")
VAULT_PORT=8200
VAULT_TOKEN=root
SAMBA_VER=4.8.12

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
TESTS_DIR=/tmp/vault_plugin_tests
WD=$(pwd)

function start_infrastructure() {
  create_network
  start_domain
  start_vault
}

function stop_infrastructure() {
  echo 'Stopping Docker containers and removing network, please wait...'
  stop_domain_joined_container
  stop_vault
  stop_domain
  delete_network
  echo 'Dev environment stopped'
  exit 0
}

function create_network() {
  docker network create ${DNS_NAME}
}

function delete_network() {
  docker network rm ${DNS_NAME}
}

function start_vault() {
  VAULT_CONTAINER=$(docker run --net=${DNS_NAME} -d -ti --cap-add=IPC_LOCK -v $(pwd)/pkg/linux_amd64:/plugins:Z -e "VAULT_DEV_ROOT_TOKEN_ID=${VAULT_TOKEN}" -e "VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:${VAULT_PORT}" -p ${VAULT_PORT}:${VAULT_PORT} vault:${VAULT_IMAGE_TAG} server -dev -dev-plugin-dir=/plugins)
  export VAULT_ADDR=http://127.0.0.1:${VAULT_PORT}
}

function stop_vault() {
  docker rm -f ${VAULT_CONTAINER}
}

function start_domain() {
  SAMBA_CONTAINER=$(docker run --net=${DNS_NAME} -d -ti --privileged -p 135:135 -p 137:137 -p 138:138 -p 139:139 -p 389:389 -p 445:445 -p 464:464 -p 636:636 -p 3268:3268 -p 3269:3269 -e "SAMBA_DC_ADMIN_PASSWD=${DOMAIN_ADMIN_PASS}" -e "KERBEROS_PASSWORD=${DOMAIN_ADMIN_PASS}" -e SAMBA_DC_DOMAIN=${DOMAIN_NAME} -e SAMBA_DC_REALM=${REALM_NAME} "bodsch/docker-samba4:${SAMBA_VER}")
  # shouldn't need to publish all these ports as they are only used within the docker network, but figured it may be useful for debugging
}

function stop_domain() {
  docker rm -f ${SAMBA_CONTAINER}
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
  mkdir -p ${TESTS_DIR}/integration
  pushd ${TESTS_DIR}/integration
  write_kerb_config
  # base64 -d $WD/grace.keytab.base64 > $TESTS_DIR/integration/grace.keytab
  eval base64 -d $WD/grace.keytab.base64 > $TESTS_DIR/integration/grace.keytab
}

function remove_files() {
  rm -fr $TESTS_DIR/integration # using superfluous child dir in case variable is blank at some point ;)
}

function start_domain_joined_container() {
  # Pull the container image first to ensure it will start up quickly,
  # because when we run in the acceptance tests, we detach and move on immediately.
  docker pull python:3.7
  DOMAIN_JOINED_CONTAINER=$(docker run --net=${DNS_NAME} -d -v "${TESTS_DIR}/integration:/tests:Z" -e KRB5_CONFIG=/tests/krb5.conf -e KRB5_CLIENT_KTNAME=/tests/grace.keytab -t python:3.7 cat)
}

function stop_domain_joined_container() {
  docker rm -f ${DOMAIN_JOINED_CONTAINER}
}

function test_joined_container() {
  docker exec $DOMAIN_JOINED_CONTAINER \
    pip install --quiet requests-kerberos kerberos
  docker cp $WD/bin/login-kerb $DOMAIN_JOINED_CONTAINER:/usr/local/bin/login-kerb
}

function prepare_outer_environment() {
  remove_files
  prepare_files
  start_domain_joined_container
  test_joined_container
}

function output_dev_vars() {
  VAULT_CONTAINER_PREFIX=${VAULT_CONTAINER:0:12}
  echo ''
  echo 'Copy and paste the following variables into your working shell:'
  echo ''
  echo "export VAULT_TOKEN=${VAULT_TOKEN}"
  echo "export VAULT_ADDR=http://localhost:8200"
  echo "export DOMAIN_DN=${DOMAIN_DN}"
  echo "export DOMAIN_JOINED_CONTAINER=${DOMAIN_JOINED_CONTAINER}"
  echo "export DOMAIN_VAULT_ACCOUNT=${DOMAIN_VAULT_ACCOUNT}"
  echo "export DOMAIN_VAULT_PASS=${DOMAIN_VAULT_PASS}"
  echo "export DOMAIN_USER_ACCOUNT=${DOMAIN_USER_ACCOUNT}"
  echo "export DNS_NAME=${DNS_NAME}"
  echo "export REALM_NAME=${REALM_NAME}"
  echo "export SAMBA_CONTAINER=${SAMBA_CONTAINER}"
  echo "export VAULT_CONTAINER=${VAULT_CONTAINER}"
  echo "export VAULT_CONTAINER_PREFIX=${VAULT_CONTAINER_PREFIX}"
  echo ''
}

function main() {
  echo 'Starting dev environment, please wait...'
  start_infrastructure
  sleep 15  # could loop until `ldapsearch` returns properly....

  # This is like a defer statement in Go, it calls a function that
  # cleans up our Docker objects and stops running Vault when we're
  # done.
  trap stop_infrastructure SIGINT

  setup_users
  add_vault_spn
  prepare_outer_environment
  echo 'Dev environment started'
  output_dev_vars

  # Now we'll hang until the user hits CTRL+C to tear everything down.
  echo 'To stop and cleanup, press CTRL+C'
  # sleep infinity
  eval "$sleepcmd"
  return 0
}
main

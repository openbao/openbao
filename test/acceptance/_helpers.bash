# vault-related env vars
VAULT_IMAGE_TAG=${VAULT_IMAGE_TAG:=$(curl -s "https://api.github.com/repos/hashicorp/vault/tags?page=1" | jq -r '.[0].name[1:]')-ent}
VAULT_IMAGE=vault-enterprise
VAULT_PORT=8200

# Set the VAULT_LICENSE from VAULT_LICENSE_PATH if set.
if [ -f "${VAULT_LICENSE_PATH}" -a -z "${VAULT_LICENSE}" ]; then
    export VAULT_LICENSE="$(cat ${VAULT_LICENSE_PATH})"
fi

# Error if the following env vars are not set
[ "${VAULT_LICENSE:?}" ]

# kerberos-related env vars
SAMBA_VER=4.8.12

export DOMAIN_ADMIN_PASS=Pa55word!
export DOMAIN_VAULT_ACCOUNT=vault_svc
export DOMAIN_VAULT_PASS=vaultPa55word!
export DOMAIN_USER_ACCOUNT=grace
DOMAIN_USER_PASS=gracePa55word!

SAMBA_CONF_FILE=/srv/etc/smb.conf
DOMAIN_NAME=matrix
export REALM_NAME=MATRIX.LAN
export DOMAIN_DN=DC=MATRIX,DC=LAN
TESTS_DIR=/tmp/vault_plugin_tests

export VAULT_CONTAINER=vault-server
export VAULT_TOKEN=root
export DNS_NAME=matrix.lan
export SAMBA_CONTAINER=samba-server
export VAULT_ADDR=http://localhost:8200
export DOMAIN_JOINED_CONTAINER=domain-joined-client

# plugin_dir returns the directory for the plugin
plugin_dir() (
    cd "${BATS_TEST_DIRNAME}/../../pkg/linux_amd64/" || return; pwd
)

function start_infrastructure() {
  create_network
  start_domain
  start_vault
}

function stop_infrastructure() {
  stop_domain_joined_container
  stop_vault
  stop_domain
  delete_network
}

create_network() {
  docker network create ${DNS_NAME}
}

delete_network() {
  docker network rm ${DNS_NAME}
}

start_vault() {
  docker run -d -ti --net=${DNS_NAME} \
    --cap-add=IPC_LOCK \
    -v "$(pwd)/pkg/linux_amd64:/plugins:Z" \
    -e "VAULT_DEV_ROOT_TOKEN_ID=${VAULT_TOKEN}" \
    -e "VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200" \
    -e "VAULT_LICENSE=${VAULT_LICENSE}" \
    -p 8200:8200 \
    --name "${VAULT_CONTAINER}" \
    "hashicorp/${VAULT_IMAGE}:${VAULT_IMAGE_TAG}" server -dev -dev-plugin-dir="/plugins"
}

stop_vault() {
  docker rm -f "${VAULT_CONTAINER}"
}

start_domain() {
  docker run \
    --net="${DNS_NAME}" \
    -d -ti --privileged \
    -p 135:135 -p 137:137 -p 138:138 -p 139:139 \
    -p 389:389 -p 445:445 -p 464:464 -p 636:636 \
    -p 3268:3268 -p 3269:3269 \
    -e "SAMBA_DC_ADMIN_PASSWD=${DOMAIN_ADMIN_PASS}" \
    -e "KERBEROS_PASSWORD=${DOMAIN_ADMIN_PASS}" \
    -e SAMBA_DC_DOMAIN="${DOMAIN_NAME}" \
    -e SAMBA_DC_REALM="${REALM_NAME}" \
    --name "${SAMBA_CONTAINER}" \
    "bodsch/docker-samba4:${SAMBA_VER}"

  echo "Waiting for samba container to become ready..."

  # Minimal sleep for the container itself to come up
  sleep 1

  samba_readiness_check() {
    # Discard stdout (but not stderr), as it's a lot of noise.
    docker exec "$SAMBA_CONTAINER" \
      ldapsearch \
        -H ldaps://localhost \
        -D "Administrator@${REALM_NAME}" \
        -w "${DOMAIN_ADMIN_PASS}" \
        -b "${DOMAIN_DN}" '(objectClass=*)' > /dev/null
  }
  declare -fxr samba_readiness_check

  timeout 60s bash -c 'until samba_readiness_check; do sleep 2; done'

  echo "Samba container ready!"
}

stop_domain() {
  docker rm -f ${SAMBA_CONTAINER}
}

setup_users() {
  add_user $DOMAIN_VAULT_ACCOUNT $DOMAIN_VAULT_PASS
  create_keytab $DOMAIN_VAULT_ACCOUNT $DOMAIN_VAULT_PASS

  add_user $DOMAIN_USER_ACCOUNT $DOMAIN_USER_PASS
  create_keytab $DOMAIN_USER_ACCOUNT $DOMAIN_USER_PASS
}

add_user() {

  username="${1}"
  password="${2}"

  if [[ $(check_user "${username}") -eq 0 ]]
  then
    echo "add user '${username}'"

    docker exec "$SAMBA_CONTAINER" \
      /usr/bin/samba-tool user create \
      "${username}" \
      "${password}"\
      --configfile="${SAMBA_CONF_FILE}"
  fi
}

check_user() {
  username="${1}"

  docker exec "$SAMBA_CONTAINER" \
    /usr/bin/samba-tool user list \
    --configfile=${SAMBA_CONF_FILE} \
    | grep -c "${username}"
}

create_keytab() {
  mkdir -p "${BATS_FILE_TMPDIR}"/integration

  username="${1}"
  password="${2}"

  user_kvno=$(docker exec "$SAMBA_CONTAINER" \
    bash -c "ldapsearch -H ldaps://localhost -D \"Administrator@${REALM_NAME}\"  -w \"${DOMAIN_ADMIN_PASS}\" -b \"CN=Users,${DOMAIN_DN}\" -LLL \"(&(objectClass=user)(sAMAccountName=${username}))\" msDS-KeyVersionNumber | sed -n 's/^[ \t]*msDS-KeyVersionNumber:[ \t]*\(.*\)/\1/p'")

  docker exec "$SAMBA_CONTAINER" \
    bash -c "printf \"%b\" \"addent -password -p \"${username}@${REALM_NAME}\" -k ${user_kvno} -e rc4-hmac\n${password}\nwrite_kt ${username}.keytab\" | ktutil"

  docker exec "$SAMBA_CONTAINER" \
    bash -c "printf \"%b\" \"read_kt ${username}.keytab\nlist\" | ktutil"

  docker exec "$SAMBA_CONTAINER" \
    base64 "${username}".keytab > "${BATS_FILE_TMPDIR}/integration/${username}.keytab.base64"
}

function add_vault_spn() {
  docker exec $SAMBA_CONTAINER \
    samba-tool spn add HTTP/"${VAULT_CONTAINER}" ${DOMAIN_VAULT_ACCOUNT} --configfile=${SAMBA_CONF_FILE}
  docker exec $SAMBA_CONTAINER \
    samba-tool spn add HTTP/"${VAULT_CONTAINER}":${VAULT_PORT} ${DOMAIN_VAULT_ACCOUNT} --configfile=${SAMBA_CONF_FILE}
  docker exec $SAMBA_CONTAINER \
    samba-tool spn add HTTP/"${VAULT_CONTAINER}".${DNS_NAME} ${DOMAIN_VAULT_ACCOUNT} --configfile=${SAMBA_CONF_FILE}
  docker exec $SAMBA_CONTAINER \
    samba-tool spn add HTTP/"${VAULT_CONTAINER}".${DNS_NAME}:${VAULT_PORT} ${DOMAIN_VAULT_ACCOUNT} --configfile=${SAMBA_CONF_FILE}
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
    kdc = ${SAMBA_CONTAINER}.${DNS_NAME}
    admin_server = ${SAMBA_CONTAINER}.${DNS_NAME}
    master_kdc = ${SAMBA_CONTAINER}.${DNS_NAME}
    default_domain = ${SAMBA_CONTAINER}.${DNS_NAME}
  }
" > krb5.conf
}

function prepare_files() {
  mkdir -p "${BATS_FILE_TMPDIR}"/integration
  pushd "${BATS_FILE_TMPDIR}"/integration
  write_kerb_config
  eval base64 -d grace.keytab.base64 > "${BATS_FILE_TMPDIR}/integration/grace.keytab"
}

function start_domain_joined_container() {
  docker run \
    --net=${DNS_NAME} \
    -d -t \
    -v "${BATS_FILE_TMPDIR}/integration:/tests:Z" \
    -e KRB5_CONFIG=/tests/krb5.conf \
    -e KRB5_CLIENT_KTNAME=/tests/grace.keytab \
    --name "${DOMAIN_JOINED_CONTAINER}" \
    python:3.7 cat
}

function stop_domain_joined_container() {
  docker rm -f ${DOMAIN_JOINED_CONTAINER}
}

function test_joined_container() {
  docker exec $DOMAIN_JOINED_CONTAINER \
    pip install --quiet requests-kerberos kerberos
}

function prepare_outer_environment() {
  prepare_files
  start_domain_joined_container
  test_joined_container
}
